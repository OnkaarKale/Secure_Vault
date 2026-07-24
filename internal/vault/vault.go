// Package vault provides high-level business operations for vault entry CRUD, integrity verification, and security auditing.
package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"securevault/internal/crypto"
	"securevault/internal/models"
	"securevault/internal/repository"
	"securevault/internal/session"
	"securevault/internal/utils"
)

// SecurityAuditReport aggregates security health findings across all stored vault entries.
type SecurityAuditReport struct {
	TotalEntries       int                  `json:"total_entries"`
	WeakPasswords      []*models.VaultEntry `json:"weak_passwords"`
	DuplicatePasswords map[string][]string  `json:"duplicate_passwords"` // password -> []title
	OldPasswords        []*models.VaultEntry `json:"old_passwords"`
	Score              int                  `json:"score"` // 0 to 100 overall vault health score
}

// VaultService handles encrypted vault operations.
type VaultService struct {
	repo      repository.VaultRepository
	auditRepo repository.AuditRepository
	session   *session.SessionManager
}

// NewVaultService creates a new VaultService instance.
func NewVaultService(repo repository.VaultRepository, auditRepo repository.AuditRepository, sess *session.SessionManager) *VaultService {
	return &VaultService{
		repo:      repo,
		auditRepo: auditRepo,
		session:   sess,
	}
}

// AddEntry encrypts and stores a new vault entry bound to active UserID.
func (v *VaultService) AddEntry(entry *models.VaultEntry) error {
	if strings.TrimSpace(entry.Title) == "" {
		return fmt.Errorf("entry title is required")
	}

	key, err := v.session.GetMasterKey()
	if err != nil {
		return err
	}
	defer utils.WipeBytes(key)

	userID := v.session.GetActiveUserID()

	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	entry.UserID = userID
	now := time.Now().UTC()
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	entry.UpdatedAt = now
	if entry.Category == "" {
		entry.Category = "General"
	}

	plainBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal vault entry: %w", err)
	}
	defer utils.WipeBytes(plainBytes)

	encPayload, err := crypto.Encrypt(plainBytes, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault entry: %w", err)
	}

	payloadBytes, err := json.Marshal(encPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted payload: %w", err)
	}

	tagsStr := strings.Join(entry.Tags, ",")

	row := &repository.EntryRow{
		ID:               entry.ID,
		UserID:           userID,
		Title:            entry.Title,
		Website:          entry.Website,
		Username:         entry.Username,
		EncryptedPayload: payloadBytes,
		Category:         entry.Category,
		Tags:             tagsStr,
		Favorite:         entry.Favorite,
		CreatedAt:        entry.CreatedAt,
		UpdatedAt:        entry.UpdatedAt,
	}

	if err := v.repo.CreateEntry(row); err != nil {
		return err
	}

	v.logAudit("CREATE_ENTRY", fmt.Sprintf("Created entry '%s' (%s)", entry.Title, entry.ID), "SUCCESS")
	return nil
}

// GetEntry retrieves and decrypts a vault entry by ID.
func (v *VaultService) GetEntry(id string) (*models.VaultEntry, error) {
	key, err := v.session.GetMasterKey()
	if err != nil {
		return nil, err
	}
	defer utils.WipeBytes(key)

	userID := v.session.GetActiveUserID()
	row, err := v.repo.GetEntryByID(userID, id)
	if err != nil {
		return nil, err
	}

	entry, err := v.decryptRow(row, key)
	if err != nil {
		return nil, err
	}

	v.logAudit("READ_ENTRY", fmt.Sprintf("Read entry '%s' (%s)", entry.Title, entry.ID), "SUCCESS")
	return entry, nil
}

// UpdateEntry re-encrypts and updates an existing entry.
func (v *VaultService) UpdateEntry(entry *models.VaultEntry) error {
	if strings.TrimSpace(entry.Title) == "" {
		return fmt.Errorf("entry title is required")
	}

	key, err := v.session.GetMasterKey()
	if err != nil {
		return err
	}
	defer utils.WipeBytes(key)

	userID := v.session.GetActiveUserID()
	entry.UserID = userID
	entry.UpdatedAt = time.Now().UTC()
	if entry.Category == "" {
		entry.Category = "General"
	}

	plainBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed marshaling entry: %w", err)
	}
	defer utils.WipeBytes(plainBytes)

	encPayload, err := crypto.Encrypt(plainBytes, key)
	if err != nil {
		return fmt.Errorf("failed encrypting entry: %w", err)
	}

	payloadBytes, err := json.Marshal(encPayload)
	if err != nil {
		return fmt.Errorf("failed marshaling payload: %w", err)
	}

	tagsStr := strings.Join(entry.Tags, ",")

	row := &repository.EntryRow{
		ID:               entry.ID,
		UserID:           userID,
		Title:            entry.Title,
		Website:          entry.Website,
		Username:         entry.Username,
		EncryptedPayload: payloadBytes,
		Category:         entry.Category,
		Tags:             tagsStr,
		Favorite:         entry.Favorite,
		CreatedAt:        entry.CreatedAt,
		UpdatedAt:        entry.UpdatedAt,
	}

	if err := v.repo.UpdateEntry(row); err != nil {
		return err
	}

	v.logAudit("UPDATE_ENTRY", fmt.Sprintf("Updated entry '%s' (%s)", entry.Title, entry.ID), "SUCCESS")
	return nil
}

// DeleteEntry removes an entry from the vault for active UserID.
func (v *VaultService) DeleteEntry(id string) error {
	userID := v.session.GetActiveUserID()
	if err := v.repo.DeleteEntry(userID, id); err != nil {
		return err
	}
	v.logAudit("DELETE_ENTRY", fmt.Sprintf("Deleted entry ID %s", id), "SUCCESS")
	return nil
}

// ListEntries decrypts and returns all stored entries for active UserID.
func (v *VaultService) ListEntries() ([]*models.VaultEntry, error) {
	key, err := v.session.GetMasterKey()
	if err != nil {
		return nil, err
	}
	defer utils.WipeBytes(key)

	userID := v.session.GetActiveUserID()
	rows, err := v.repo.ListEntries(userID)
	if err != nil {
		return nil, err
	}

	var entries []*models.VaultEntry
	for _, row := range rows {
		entry, err := v.decryptRow(row, key)
		if err != nil {
			return nil, fmt.Errorf("failed decrypting entry %s: %w", row.ID, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// ToggleFavorite flips the favorite status of a given entry.
func (v *VaultService) ToggleFavorite(id string) (bool, error) {
	entry, err := v.GetEntry(id)
	if err != nil {
		return false, err
	}

	userID := v.session.GetActiveUserID()
	newFav := !entry.Favorite
	if err := v.repo.ToggleFavorite(userID, id, newFav); err != nil {
		return false, err
	}

	v.logAudit("TOGGLE_FAVORITE", fmt.Sprintf("Toggled favorite for '%s' to %v", entry.Title, newFav), "SUCCESS")
	return newFav, nil
}

// AuditSecurity checks for weak, duplicate, or old passwords across the active user's vault.
func (v *VaultService) AuditSecurity() (*SecurityAuditReport, error) {
	entries, err := v.ListEntries()
	if err != nil {
		return nil, err
	}

	report := &SecurityAuditReport{
		TotalEntries:       len(entries),
		DuplicatePasswords: make(map[string][]string),
		Score:              100,
	}

	if len(entries) == 0 {
		return report, nil
	}

	passMap := make(map[string][]string)
	now := time.Now()

	for _, entry := range entries {
		entropy := utils.CalculateEntropy(entry.Password)
		if entropy < 40.0 || len(entry.Password) < 10 {
			report.WeakPasswords = append(report.WeakPasswords, entry)
		}

		if entry.Password != "" {
			passMap[entry.Password] = append(passMap[entry.Password], entry.Title)
		}

		if now.Sub(entry.UpdatedAt) > 90*24*time.Hour {
			report.OldPasswords = append(report.OldPasswords, entry)
		}
	}

	for pass, titles := range passMap {
		if len(titles) > 1 {
			report.DuplicatePasswords[pass] = titles
		}
	}

	penalty := len(report.WeakPasswords)*15 + len(report.DuplicatePasswords)*20 + len(report.OldPasswords)*5
	report.Score = 100 - penalty
	if report.Score < 0 {
		report.Score = 0
	}

	v.logAudit("SECURITY_AUDIT", fmt.Sprintf("Audit completed with score %d/100", report.Score), "SUCCESS")
	return report, nil
}

// VerifyIntegrity checks if all stored entry payloads for active UserID can be decrypted without MAC/GCM errors.
func (v *VaultService) VerifyIntegrity() error {
	key, err := v.session.GetMasterKey()
	if err != nil {
		return err
	}
	defer utils.WipeBytes(key)

	userID := v.session.GetActiveUserID()
	rows, err := v.repo.ListEntries(userID)
	if err != nil {
		return err
	}

	for _, row := range rows {
		_, err := v.decryptRow(row, key)
		if err != nil {
			v.logAudit("INTEGRITY_CHECK", fmt.Sprintf("Tamper detected on entry ID %s", row.ID), "CORRUPTED")
			return fmt.Errorf("integrity verification failed for entry %s: %w", row.ID, err)
		}
	}

	v.logAudit("INTEGRITY_CHECK", fmt.Sprintf("Verified integrity of %d entries", len(rows)), "SUCCESS")
	return nil
}

func (v *VaultService) decryptRow(row *repository.EntryRow, key []byte) (*models.VaultEntry, error) {
	var payload models.EncryptedPayload
	if err := json.Unmarshal(row.EncryptedPayload, &payload); err != nil {
		return nil, fmt.Errorf("failed parsing payload JSON: %w", err)
	}

	plainBytes, err := crypto.Decrypt(&payload, key)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %w", err)
	}
	defer utils.WipeBytes(plainBytes)

	var entry models.VaultEntry
	if err := json.Unmarshal(plainBytes, &entry); err != nil {
		return nil, fmt.Errorf("failed unmarshaling entry JSON: %w", err)
	}

	if entry.Tags == nil && row.Tags != "" {
		entry.Tags = strings.Split(row.Tags, ",")
	}

	return &entry, nil
}

func (v *VaultService) logAudit(action, details, status string) {
	userID := v.session.GetActiveUserID()
	logItem := &models.AuditLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		Action:    action,
		Details:   details,
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
	_ = v.auditRepo.CreateLog(logItem)
}
