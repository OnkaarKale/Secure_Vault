// Package repository defines data access interfaces and SQLite implementations following clean architecture.
package repository

import (
	"time"

	"securevault/internal/models"
)

// EntryRow represents a persistent database row for a vault entry before decryption.
type EntryRow struct {
	ID               string
	UserID           string
	Title            string
	Website          string
	Username         string
	EncryptedPayload []byte
	Category         string
	Tags             string
	Favorite         bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// UserRepository defines operations for managing user accounts.
type UserRepository interface {
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	UpdateUser(user *models.User) error
	CountUsers() (int, error)
}

// AuthRepository defines operations for reading and writing vault metadata and master authentication configuration.
type AuthRepository interface {
	GetMetadata() (*models.VaultMetadata, error)
	SaveMetadata(meta *models.VaultMetadata) error
}

// VaultRepository defines CRUD operations for persistent vault entries isolated by UserID.
type VaultRepository interface {
	CreateEntry(row *EntryRow) error
	UpdateEntry(row *EntryRow) error
	DeleteEntry(userID, id string) error
	GetEntryByID(userID, id string) (*EntryRow, error)
	ListEntries(userID string) ([]*EntryRow, error)
	ToggleFavorite(userID, id string, favorite bool) error
	DeleteAllEntries(userID string) error
}

// AuditRepository defines persistence methods for security audit logs.
type AuditRepository interface {
	CreateLog(log *models.AuditLog) error
	ListLogs(userID string, limit int) ([]*models.AuditLog, error)
}
