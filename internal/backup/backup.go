// Package backup manages encrypted vault backup creation, rotation policy, and restoration.
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"securevault/internal/crypto"
	"securevault/internal/models"
	"securevault/internal/repository"
	"securevault/internal/session"
	"securevault/internal/utils"
)

// BackupPackage represents the unencrypted payload structure of a vault backup snapshot.
type BackupPackage struct {
	Version   string                `json:"version"`
	Timestamp time.Time             `json:"timestamp"`
	Metadata  *models.VaultMetadata `json:"metadata"`
	Entries   []*models.VaultEntry  `json:"entries"`
}

// BackupService handles snapshot generation and restoration.
type BackupService struct {
	authRepo  repository.AuthRepository
	vaultRepo repository.VaultRepository
	auditRepo repository.AuditRepository
	session   *session.SessionManager
	config    *models.AppConfig
}

// NewBackupService creates a BackupService instance.
func NewBackupService(authRepo repository.AuthRepository, vaultRepo repository.VaultRepository, auditRepo repository.AuditRepository, sess *session.SessionManager, cfg *models.AppConfig) *BackupService {
	return &BackupService{
		authRepo:  authRepo,
		vaultRepo: vaultRepo,
		auditRepo: auditRepo,
		session:   sess,
		config:    cfg,
	}
}

func (b *BackupService) getBackupDir() string {
	if b.config != nil && strings.TrimSpace(b.config.BackupDir) != "" {
		return b.config.BackupDir
	}
	return "./backups"
}

// CreateBackup exports an encrypted backup snapshot of the vault to default backup dir.
func (b *BackupService) CreateBackup() (*models.BackupMetadata, error) {
	return b.CreateBackupToPath("")
}

// CreateBackupToPath exports an encrypted backup snapshot of the vault to a custom file or directory path.
func (b *BackupService) CreateBackupToPath(targetPath string) (*models.BackupMetadata, error) {
	key, err := b.session.GetMasterKey()
	if err != nil {
		return nil, err
	}
	defer utils.WipeBytes(key)

	meta, err := b.authRepo.GetMetadata()
	if meta == nil {
		currUser := b.session.GetCurrentUser()
		meta = &models.VaultMetadata{
			Initialized:  true,
			VaultID:      "vault-default",
			Argon2Params: models.DefaultArgon2Params(),
		}
		if currUser != nil {
			meta.VaultID = currUser.ID
			meta.MasterHash = currUser.MasterHash
			meta.MasterSalt = currUser.MasterSalt
			meta.Argon2Params = currUser.Argon2Params
			meta.CreatedAt = currUser.CreatedAt
			meta.UpdatedAt = currUser.UpdatedAt
		}
	}

	userID := b.session.GetActiveUserID()
	rows, err := b.vaultRepo.ListEntries(userID)
	if err != nil {
		return nil, fmt.Errorf("failed fetching entries for backup: %w", err)
	}

	var entries []*models.VaultEntry
	for _, row := range rows {
		var payload models.EncryptedPayload
		if err := json.Unmarshal(row.EncryptedPayload, &payload); err != nil {
			return nil, fmt.Errorf("corrupted entry payload in DB: %w", err)
		}
		plainBytes, err := crypto.Decrypt(&payload, key)
		if err != nil {
			return nil, fmt.Errorf("failed decrypting entry %s during backup: %w", row.ID, err)
		}
		var entry models.VaultEntry
		if err := json.Unmarshal(plainBytes, &entry); err != nil {
			utils.WipeBytes(plainBytes)
			return nil, fmt.Errorf("corrupted JSON for entry %s: %w", row.ID, err)
		}
		utils.WipeBytes(plainBytes)
		entries = append(entries, &entry)
	}

	pkg := BackupPackage{
		Version:   "1.0",
		Timestamp: time.Now().UTC(),
		Metadata:  meta,
		Entries:   entries,
	}

	pkgBytes, err := json.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling backup package: %w", err)
	}
	defer utils.WipeBytes(pkgBytes)

	encPayload, err := crypto.Encrypt(pkgBytes, key)
	if err != nil {
		return nil, fmt.Errorf("failed encrypting backup package: %w", err)
	}

	encBytes, err := json.Marshal(encPayload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling encrypted backup JSON: %w", err)
	}

	// Resolve destination file path
	cleanTarget := strings.TrimSpace(targetPath)
	filename := fmt.Sprintf("securevault_backup_%s.svb", pkg.Timestamp.Format("20060102_150405"))
	var filePath string

	if cleanTarget == "" {
		backupDir := b.getBackupDir()
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			return nil, fmt.Errorf("failed creating backup directory: %w", err)
		}
		filePath = filepath.Join(backupDir, filename)
	} else {
		fi, err := os.Stat(cleanTarget)
		if err == nil && fi.IsDir() {
			filePath = filepath.Join(cleanTarget, filename)
		} else if strings.HasSuffix(cleanTarget, "/") || strings.HasSuffix(cleanTarget, "\\") {
			if err := os.MkdirAll(cleanTarget, 0700); err != nil {
				return nil, fmt.Errorf("failed creating target directory: %w", err)
			}
			filePath = filepath.Join(cleanTarget, filename)
		} else {
			dir := filepath.Dir(cleanTarget)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, fmt.Errorf("failed creating parent directory: %w", err)
			}
			filePath = cleanTarget
		}
	}

	if err := os.WriteFile(filePath, encBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed writing backup file: %w", err)
	}

	hash := sha256.Sum256(encBytes)
	checksum := hex.EncodeToString(hash[:])

	bmeta := &models.BackupMetadata{
		ID:         uuid.New().String(),
		Timestamp:  pkg.Timestamp,
		Version:    pkg.Version,
		EntryCount: len(entries),
		FilePath:   filePath,
		Checksum:   checksum,
	}

	_ = b.RotateBackups()

	b.logAudit("CREATE_BACKUP", fmt.Sprintf("Created backup file %s (%d entries)", filepath.Base(filePath), len(entries)), "SUCCESS")
	return bmeta, nil
}

// InspectBackup decrypts snapshot package header and returns package info without mutating database.
func (b *BackupService) InspectBackup(filePath string) (*BackupPackage, error) {
	key, err := b.session.GetMasterKey()
	if err != nil {
		return nil, err
	}
	defer utils.WipeBytes(key)

	encBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading backup file: %w", err)
	}

	var payload models.EncryptedPayload
	if err := json.Unmarshal(encBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid or corrupted backup file format: %w", err)
	}

	plainBytes, err := crypto.Decrypt(&payload, key)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting backup (invalid master key or tampered file): %w", err)
	}
	defer utils.WipeBytes(plainBytes)

	var pkg BackupPackage
	if err := json.Unmarshal(plainBytes, &pkg); err != nil {
		return nil, fmt.Errorf("failed parsing backup contents: %w", err)
	}

	return &pkg, nil
}

// ListBackups scans the backup directory and returns metadata for existing backups.
func (b *BackupService) ListBackups() ([]*models.BackupMetadata, error) {
	backupDir := b.getBackupDir()
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return nil, nil
	}

	files, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed reading backup directory: %w", err)
	}

	var backups []*models.BackupMetadata

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".svb") {
			continue
		}

		filePath := filepath.Join(backupDir, f.Name())
		info, err := f.Info()
		if err != nil {
			continue
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(data)
		checksum := hex.EncodeToString(hash[:])

		backups = append(backups, &models.BackupMetadata{
			ID:        f.Name(),
			Timestamp: info.ModTime(),
			Version:   "1.0",
			FilePath:  filePath,
			Checksum:  checksum,
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp.After(backups[j].Timestamp)
	})

	return backups, nil
}

// RestoreBackup decrypts a snapshot and restores vault entries.
func (b *BackupService) RestoreBackup(filePath string) error {
	key, err := b.session.GetMasterKey()
	if err != nil {
		return err
	}
	defer utils.WipeBytes(key)

	encBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading backup file: %w", err)
	}

	var payload models.EncryptedPayload
	if err := json.Unmarshal(encBytes, &payload); err != nil {
		return fmt.Errorf("invalid or corrupted backup file format: %w", err)
	}

	plainBytes, err := crypto.Decrypt(&payload, key)
	if err != nil {
		return fmt.Errorf("failed decrypting backup (invalid master key or tampered file): %w", err)
	}
	defer utils.WipeBytes(plainBytes)

	var pkg BackupPackage
	if err := json.Unmarshal(plainBytes, &pkg); err != nil {
		return fmt.Errorf("failed parsing backup contents: %w", err)
	}

	userID := b.session.GetActiveUserID()
	if err := b.vaultRepo.DeleteAllEntries(userID); err != nil {
		return fmt.Errorf("failed clearing current entries for restore: %w", err)
	}

	for _, entry := range pkg.Entries {
		entry.UserID = userID
		entryPlain, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed marshaling entry %s: %w", entry.ID, err)
		}

		encPayload, err := crypto.Encrypt(entryPlain, key)
		utils.WipeBytes(entryPlain)
		if err != nil {
			return fmt.Errorf("failed encrypting entry %s: %w", entry.ID, err)
		}

		pBytes, err := json.Marshal(encPayload)
		if err != nil {
			return fmt.Errorf("failed marshaling payload %s: %w", entry.ID, err)
		}

		tagsStr := strings.Join(entry.Tags, ",")
		row := &repository.EntryRow{
			ID:               entry.ID,
			UserID:           userID,
			Title:            entry.Title,
			Website:          entry.Website,
			Username:         entry.Username,
			EncryptedPayload: pBytes,
			Category:         entry.Category,
			Tags:             tagsStr,
			Favorite:         entry.Favorite,
			CreatedAt:        entry.CreatedAt,
			UpdatedAt:        entry.UpdatedAt,
		}

		if err := b.vaultRepo.CreateEntry(row); err != nil {
			return fmt.Errorf("failed restoring entry %s: %w", entry.ID, err)
		}
	}

	b.logAudit("RESTORE_BACKUP", fmt.Sprintf("Restored %d entries from backup %s", len(pkg.Entries), filepath.Base(filePath)), "SUCCESS")
	return nil
}

// RotateBackups retains only the most recent N backup snapshots.
func (b *BackupService) RotateBackups() error {
	maxRotation := 10
	if b.config != nil && b.config.BackupRotationCount > 0 {
		maxRotation = b.config.BackupRotationCount
	}

	backups, err := b.ListBackups()
	if err != nil || len(backups) <= maxRotation {
		return nil
	}

	for i := maxRotation; i < len(backups); i++ {
		_ = os.Remove(backups[i].FilePath)
	}

	return nil
}

func (b *BackupService) logAudit(action, details, status string) {
	userID := b.session.GetActiveUserID()
	logItem := &models.AuditLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		Action:    action,
		Details:   details,
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
	_ = b.auditRepo.CreateLog(logItem)
}
