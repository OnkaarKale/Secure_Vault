// Package auth manages master password verification, user registration, and multi-user authentication.
package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"securevault/internal/crypto"
	"securevault/internal/logger"
	"securevault/internal/models"
	"securevault/internal/repository"
	"securevault/internal/session"
	"securevault/internal/utils"
)

// AuthService handles multi-user authentication, registration, and session unlocking.
type AuthService struct {
	userRepo  repository.UserRepository
	authRepo  repository.AuthRepository
	vaultRepo repository.VaultRepository
	auditRepo repository.AuditRepository
	session   *session.SessionManager
	config    *models.AppConfig
}

// NewAuthService constructs a new AuthService.
func NewAuthService(userRepo repository.UserRepository, authRepo repository.AuthRepository, vaultRepo repository.VaultRepository, auditRepo repository.AuditRepository, sess *session.SessionManager, cfg *models.AppConfig) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		authRepo:  authRepo,
		vaultRepo: vaultRepo,
		auditRepo: auditRepo,
		session:   sess,
		config:    cfg,
	}
}

// SignUp registers a new user with an email/gmail username and master password.
func (a *AuthService) SignUp(email, masterPassword string) (*models.User, error) {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	if cleanEmail == "" || !strings.Contains(cleanEmail, "@") {
		return nil, fmt.Errorf("valid email or Gmail username is required")
	}

	if len(masterPassword) < 8 {
		return nil, fmt.Errorf("master password must be at least 8 characters long")
	}

	existing, err := a.userRepo.GetUserByEmail(cleanEmail)
	if err != nil {
		return nil, fmt.Errorf("failed checking existing user: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("an account with email '%s' already exists", cleanEmail)
	}

	params := models.DefaultArgon2Params()
	salt, err := crypto.GenerateSalt(params.SaltLen)
	if err != nil {
		return nil, fmt.Errorf("failed generating salt: %w", err)
	}

	masterHashBytes, err := crypto.HashMasterPassword(masterPassword, salt, params)
	if err != nil {
		utils.WipeBytes(salt)
		return nil, fmt.Errorf("failed hashing master password: %w", err)
	}
	defer utils.WipeBytes(masterHashBytes)

	user := &models.User{
		ID:           uuid.New().String(),
		Email:        cleanEmail,
		MasterHash:   fmt.Sprintf("%x", masterHashBytes),
		MasterSalt:   salt,
		Argon2Params: params,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := a.userRepo.CreateUser(user); err != nil {
		return nil, fmt.Errorf("failed saving user record: %w", err)
	}

	// Derive key and unlock session immediately for new signup
	derivedKey := crypto.DeriveKey(masterPassword, user.MasterSalt, user.Argon2Params)
	if err := a.session.Unlock(derivedKey, user); err != nil {
		utils.WipeBytes(derivedKey)
		return nil, err
	}

	a.logAudit(user.ID, "SIGNUP", fmt.Sprintf("Account registered for %s", cleanEmail), "SUCCESS")
	logger.Info("New user account registered: %s", cleanEmail)

	return user, nil
}

// Login authenticates a user by email and master password and unlocks their isolated vault.
func (a *AuthService) Login(email, masterPassword string) ([]byte, *models.User, error) {
	if locked, remaining := a.session.IsLockedOut(); locked {
		a.logAudit("", "LOGIN_ATTEMPT", "Login rejected due to lockout", "LOCKED")
		return nil, nil, fmt.Errorf("account locked out. Try again in %v", remaining.Round(time.Second))
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	user, err := a.userRepo.GetUserByEmail(cleanEmail)
	if err != nil || user == nil {
		attempts, lockout := a.session.RecordFailedAttempt()
		a.logAudit("", "LOGIN_ATTEMPT", fmt.Sprintf("Failed login for %s", cleanEmail), "FAILURE")
		if !lockout.IsZero() {
			return nil, nil, fmt.Errorf("invalid email or master password. Locked for %d minutes", a.config.LockoutDurationMinutes)
		}
		return nil, nil, fmt.Errorf("invalid email or master password (attempt %d of %d)", attempts, a.config.MaxLoginAttempts)
	}

	var targetHashBytes []byte
	_, err = fmt.Sscanf(user.MasterHash, "%x", &targetHashBytes)
	if err != nil || len(targetHashBytes) == 0 {
		return nil, nil, fmt.Errorf("corrupted master password data for user")
	}

	valid := crypto.VerifyMasterPassword(masterPassword, user.MasterSalt, targetHashBytes, user.Argon2Params)
	if !valid {
		attempts, lockout := a.session.RecordFailedAttempt()
		a.logAudit(user.ID, "LOGIN_ATTEMPT", fmt.Sprintf("Failed password attempt for %s", cleanEmail), "FAILURE")
		if !lockout.IsZero() {
			return nil, nil, fmt.Errorf("invalid master password. Account locked for %d minutes", a.config.LockoutDurationMinutes)
		}
		return nil, nil, fmt.Errorf("invalid master password (attempt %d of %d)", attempts, a.config.MaxLoginAttempts)
	}

	// Derive user master key
	derivedKey := crypto.DeriveKey(masterPassword, user.MasterSalt, user.Argon2Params)
	if err := a.session.Unlock(derivedKey, user); err != nil {
		utils.WipeBytes(derivedKey)
		return nil, nil, err
	}

	a.logAudit(user.ID, "LOGIN_ATTEMPT", fmt.Sprintf("User %s authenticated successfully", cleanEmail), "SUCCESS")
	return derivedKey, user, nil
}

// SignOut locks active session and wipes memory keys.
func (a *AuthService) SignOut() {
	currUser := a.session.GetCurrentUser()
	userID := ""
	if currUser != nil {
		userID = currUser.ID
	}
	a.session.Lock()
	a.logAudit(userID, "SIGNOUT", "User signed out of vault session", "SUCCESS")
}

// IsInitialized returns true if at least one user account or legacy vault exists.
func (a *AuthService) IsInitialized() (bool, error) {
	count, err := a.userRepo.CountUsers()
	if err == nil && count > 0 {
		return true, nil
	}

	meta, err := a.authRepo.GetMetadata()
	if err != nil {
		return false, nil
	}
	if meta == nil {
		return false, nil
	}
	return meta.Initialized, nil
}

// Authenticate provides fallback single-user CLI master password verification.
func (a *AuthService) Authenticate(masterPassword string) ([]byte, error) {
	currUser := a.session.GetCurrentUser()
	if currUser != nil {
		key, _, err := a.Login(currUser.Email, masterPassword)
		return key, err
	}

	meta, err := a.authRepo.GetMetadata()
	if err != nil || meta == nil || !meta.Initialized {
		return nil, fmt.Errorf("vault is not initialized")
	}

	var targetHashBytes []byte
	_, err = fmt.Sscanf(meta.MasterHash, "%x", &targetHashBytes)
	if err != nil || len(targetHashBytes) == 0 {
		return nil, fmt.Errorf("corrupted master password metadata")
	}

	valid := crypto.VerifyMasterPassword(masterPassword, meta.MasterSalt, targetHashBytes, meta.Argon2Params)
	if !valid {
		attempts, lockout := a.session.RecordFailedAttempt()
		if !lockout.IsZero() {
			return nil, fmt.Errorf("invalid master password. Account locked for %d minutes", a.config.LockoutDurationMinutes)
		}
		return nil, fmt.Errorf("invalid master password (attempt %d of %d)", attempts, a.config.MaxLoginAttempts)
	}

	derivedKey := crypto.DeriveKey(masterPassword, meta.MasterSalt, meta.Argon2Params)
	if err := a.session.Unlock(derivedKey, nil); err != nil {
		utils.WipeBytes(derivedKey)
		return nil, err
	}

	return derivedKey, nil
}

// InitializeVault provides fallback initialization for CLI.
func (a *AuthService) InitializeVault(masterPassword string) error {
	_, err := a.SignUp("default@securevault.local", masterPassword)
	return err
}

// Logout locks active session.
func (a *AuthService) Logout() {
	a.SignOut()
}

// ChangeMasterPassword updates master password and re-encrypts all user entries.
func (a *AuthService) ChangeMasterPassword(currentPassword, newPassword string) error {
	currUser := a.session.GetCurrentUser()
	if currUser == nil {
		return fmt.Errorf("no user signed in")
	}

	oldKey, _, err := a.Login(currUser.Email, currentPassword)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer utils.WipeBytes(oldKey)

	rows, err := a.vaultRepo.ListEntries(currUser.ID)
	if err != nil {
		return fmt.Errorf("failed fetching entries for re-encryption: %w", err)
	}

	type decryptedHolder struct {
		row   *repository.EntryRow
		entry *models.VaultEntry
	}
	var holders []decryptedHolder

	for _, row := range rows {
		var payload models.EncryptedPayload
		if err := json.Unmarshal(row.EncryptedPayload, &payload); err != nil {
			return fmt.Errorf("failed parsing payload for entry %s: %w", row.ID, err)
		}

		plainBytes, err := crypto.Decrypt(&payload, oldKey)
		if err != nil {
			return fmt.Errorf("failed decrypting entry %s: %w", row.ID, err)
		}

		var entry models.VaultEntry
		if err := json.Unmarshal(plainBytes, &entry); err != nil {
			utils.WipeBytes(plainBytes)
			return fmt.Errorf("failed unmarshaling entry %s: %w", row.ID, err)
		}
		utils.WipeBytes(plainBytes)

		holders = append(holders, decryptedHolder{row: row, entry: &entry})
	}

	newSalt, err := crypto.GenerateSalt(currUser.Argon2Params.SaltLen)
	if err != nil {
		return fmt.Errorf("failed generating new salt: %w", err)
	}

	newKeyBytes, err := crypto.HashMasterPassword(newPassword, newSalt, currUser.Argon2Params)
	if err != nil {
		utils.WipeBytes(newSalt)
		return fmt.Errorf("failed hashing new master password: %w", err)
	}
	defer utils.WipeBytes(newKeyBytes)

	newDerivationKey := crypto.DeriveKey(newPassword, newSalt, currUser.Argon2Params)
	defer utils.WipeBytes(newDerivationKey)

	for _, h := range holders {
		plainBytes, err := json.Marshal(h.entry)
		if err != nil {
			return fmt.Errorf("failed marshaling entry %s: %w", h.entry.ID, err)
		}

		encPayload, err := crypto.Encrypt(plainBytes, newDerivationKey)
		utils.WipeBytes(plainBytes)
		if err != nil {
			return fmt.Errorf("failed re-encrypting entry %s: %w", h.entry.ID, err)
		}

		payloadBytes, err := json.Marshal(encPayload)
		if err != nil {
			return fmt.Errorf("failed marshaling payload %s: %w", h.entry.ID, err)
		}

		h.row.EncryptedPayload = payloadBytes
		h.row.UpdatedAt = time.Now().UTC()

		if err := a.vaultRepo.UpdateEntry(h.row); err != nil {
			return fmt.Errorf("failed updating entry %s: %w", h.entry.ID, err)
		}
	}

	currUser.MasterSalt = newSalt
	currUser.MasterHash = fmt.Sprintf("%x", newKeyBytes)
	currUser.UpdatedAt = time.Now().UTC()

	if err := a.userRepo.UpdateUser(currUser); err != nil {
		return fmt.Errorf("failed updating user record: %w", err)
	}

	_ = a.session.Unlock(newDerivationKey, currUser)

	a.logAudit(currUser.ID, "CHANGE_MASTER_PASSWORD", "Master password updated successfully", "SUCCESS")
	return nil
}

func (a *AuthService) logAudit(userID, action, details, status string) {
	logItem := &models.AuditLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		Action:    action,
		Details:   details,
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
	_ = a.auditRepo.CreateLog(logItem)
}
