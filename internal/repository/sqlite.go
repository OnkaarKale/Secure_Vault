// Package repository implements SQLite database persistence for users, metadata, entries, and audit logs.
package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"securevault/internal/models"
)

// SQLiteRepository provides data access implementation over an sql.DB connection pool.
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository constructs a new SQLiteRepository instance.
func NewSQLiteRepository(db *sql.DB) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

// CreateUser inserts a new user record.
func (r *SQLiteRepository) CreateUser(user *models.User) error {
	paramsBytes, err := json.Marshal(user.Argon2Params)
	if err != nil {
		return fmt.Errorf("failed to marshal argon2 params: %w", err)
	}

	query := `INSERT INTO users (id, email, master_hash, master_salt, argon2_params, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = r.db.Exec(query, user.ID, strings.ToLower(strings.TrimSpace(user.Email)), user.MasterHash, user.MasterSalt, string(paramsBytes), user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed creating user record: %w", err)
	}
	return nil
}

// GetUserByEmail retrieves a user by unique email/gmail.
func (r *SQLiteRepository) GetUserByEmail(email string) (*models.User, error) {
	query := `SELECT id, email, master_hash, master_salt, argon2_params, created_at, updated_at FROM users WHERE email = ?`
	row := r.db.QueryRow(query, strings.ToLower(strings.TrimSpace(email)))

	var u models.User
	var paramsJSON string

	err := row.Scan(&u.ID, &u.Email, &u.MasterHash, &u.MasterSalt, &paramsJSON, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed querying user by email: %w", err)
	}

	if err := json.Unmarshal([]byte(paramsJSON), &u.Argon2Params); err != nil {
		return nil, fmt.Errorf("failed parsing argon2 params: %w", err)
	}

	return &u, nil
}

// GetUserByID retrieves a user record by ID.
func (r *SQLiteRepository) GetUserByID(id string) (*models.User, error) {
	query := `SELECT id, email, master_hash, master_salt, argon2_params, created_at, updated_at FROM users WHERE id = ?`
	row := r.db.QueryRow(query, id)

	var u models.User
	var paramsJSON string

	err := row.Scan(&u.ID, &u.Email, &u.MasterHash, &u.MasterSalt, &paramsJSON, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed querying user by id: %w", err)
	}

	if err := json.Unmarshal([]byte(paramsJSON), &u.Argon2Params); err != nil {
		return nil, fmt.Errorf("failed parsing argon2 params: %w", err)
	}

	return &u, nil
}

// UpdateUser updates a user's master hash and salt.
func (r *SQLiteRepository) UpdateUser(user *models.User) error {
	paramsBytes, err := json.Marshal(user.Argon2Params)
	if err != nil {
		return fmt.Errorf("failed marshaling params: %w", err)
	}

	query := `UPDATE users SET master_hash = ?, master_salt = ?, argon2_params = ?, updated_at = ? WHERE id = ?`
	res, err := r.db.Exec(query, user.MasterHash, user.MasterSalt, string(paramsBytes), user.UpdatedAt, user.ID)
	if err != nil {
		return fmt.Errorf("failed updating user: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return fmt.Errorf("user not found for update: %s", user.ID)
	}
	return nil
}

// CountUsers returns total registered user accounts.
func (r *SQLiteRepository) CountUsers() (int, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetMetadata fetches the singleton vault metadata record.
func (r *SQLiteRepository) GetMetadata() (*models.VaultMetadata, error) {
	query := `SELECT vault_id, initialized, master_hash, master_salt, argon2_params, created_at, updated_at FROM vault_meta WHERE id = 1`
	row := r.db.QueryRow(query)

	var meta models.VaultMetadata
	var initInt int
	var paramsJSON string

	err := row.Scan(&meta.VaultID, &initInt, &meta.MasterHash, &meta.MasterSalt, &paramsJSON, &meta.CreatedAt, &meta.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query vault metadata: %w", err)
	}

	meta.Initialized = (initInt == 1)
	if err := json.Unmarshal([]byte(paramsJSON), &meta.Argon2Params); err != nil {
		return nil, fmt.Errorf("failed to parse argon2 params: %w", err)
	}

	return &meta, nil
}

// SaveMetadata inserts or updates the singleton vault metadata record.
func (r *SQLiteRepository) SaveMetadata(meta *models.VaultMetadata) error {
	paramsBytes, err := json.Marshal(meta.Argon2Params)
	if err != nil {
		return fmt.Errorf("failed to marshal argon2 params: %w", err)
	}

	initInt := 0
	if meta.Initialized {
		initInt = 1
	}

	query := `INSERT INTO vault_meta (id, vault_id, initialized, master_hash, master_salt, argon2_params, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			initialized=excluded.initialized,
			master_hash=excluded.master_hash,
			master_salt=excluded.master_salt,
			argon2_params=excluded.argon2_params,
			updated_at=excluded.updated_at`

	_, err = r.db.Exec(query, meta.VaultID, initInt, meta.MasterHash, meta.MasterSalt, string(paramsBytes), meta.CreatedAt, meta.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to save vault metadata: %w", err)
	}
	return nil
}

// CreateEntry inserts a new entry into the database.
func (r *SQLiteRepository) CreateEntry(entry *EntryRow) error {
	query := `INSERT INTO vault_entries (id, user_id, title, website, username, encrypted_payload, category, tags, favorite, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	favInt := 0
	if entry.Favorite {
		favInt = 1
	}

	_, err := r.db.Exec(query, entry.ID, entry.UserID, entry.Title, entry.Website, entry.Username, entry.EncryptedPayload, entry.Category, entry.Tags, favInt, entry.CreatedAt, entry.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert entry %s: %w", entry.ID, err)
	}
	return nil
}

// UpdateEntry updates an existing vault entry row.
func (r *SQLiteRepository) UpdateEntry(entry *EntryRow) error {
	query := `UPDATE vault_entries SET title=?, website=?, username=?, encrypted_payload=?, category=?, tags=?, favorite=?, updated_at=? WHERE (id = ? OR id LIKE ? || '%') AND (user_id = ? OR user_id = '')`

	favInt := 0
	if entry.Favorite {
		favInt = 1
	}

	res, err := r.db.Exec(query, entry.Title, entry.Website, entry.Username, entry.EncryptedPayload, entry.Category, entry.Tags, favInt, entry.UpdatedAt, entry.ID, entry.ID, entry.UserID)
	if err != nil {
		return fmt.Errorf("failed to update entry %s: %w", entry.ID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("entry with ID %s not found", entry.ID)
	}
	return nil
}

// DeleteEntry removes an entry by ID or short prefix and UserID.
func (r *SQLiteRepository) DeleteEntry(userID, id string) error {
	query := `DELETE FROM vault_entries WHERE (id = ? OR id LIKE ? || '%') AND (user_id = ? OR user_id = '')`
	res, err := r.db.Exec(query, id, id, userID)
	if err != nil {
		return fmt.Errorf("failed to delete entry %s: %w", id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("entry not found: %s", id)
	}
	return nil
}

// GetEntryByID retrieves a single entry row by ID or short prefix and UserID.
func (r *SQLiteRepository) GetEntryByID(userID, id string) (*EntryRow, error) {
	query := `SELECT id, user_id, title, website, username, encrypted_payload, category, tags, favorite, created_at, updated_at FROM vault_entries WHERE (id = ? OR id LIKE ? || '%') AND (user_id = ? OR user_id = '') LIMIT 1`
	row := r.db.QueryRow(query, id, id, userID)

	var entry EntryRow
	var favInt int
	err := row.Scan(&entry.ID, &entry.UserID, &entry.Title, &entry.Website, &entry.Username, &entry.EncryptedPayload, &entry.Category, &entry.Tags, &favInt, &entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("entry not found: %s", id)
		}
		return nil, fmt.Errorf("failed to scan entry: %w", err)
	}

	entry.Favorite = (favInt == 1)
	return &entry, nil
}

// ListEntries returns all stored entry rows for a specific UserID.
func (r *SQLiteRepository) ListEntries(userID string) ([]*EntryRow, error) {
	query := `SELECT id, user_id, title, website, username, encrypted_payload, category, tags, favorite, created_at, updated_at FROM vault_entries WHERE user_id = ? OR user_id = '' ORDER BY title ASC`
	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list entries: %w", err)
	}
	defer rows.Close()

	var results []*EntryRow
	for rows.Next() {
		var entry EntryRow
		var favInt int
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Title, &entry.Website, &entry.Username, &entry.EncryptedPayload, &entry.Category, &entry.Tags, &favInt, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning entry row: %w", err)
		}
		entry.Favorite = (favInt == 1)
		results = append(results, &entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating entry rows: %w", err)
	}

	return results, nil
}

// ToggleFavorite sets the favorite flag for a specific entry by ID or short prefix.
func (r *SQLiteRepository) ToggleFavorite(userID, id string, favorite bool) error {
	query := `UPDATE vault_entries SET favorite = ?, updated_at = ? WHERE (id = ? OR id LIKE ? || '%') AND (user_id = ? OR user_id = '')`
	favInt := 0
	if favorite {
		favInt = 1
	}
	res, err := r.db.Exec(query, favInt, time.Now().UTC(), id, id, userID)
	if err != nil {
		return fmt.Errorf("failed to toggle favorite for entry %s: %w", id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("entry not found: %s", id)
	}
	return nil
}

// DeleteAllEntries purges all vault entry records for a specific UserID.
func (r *SQLiteRepository) DeleteAllEntries(userID string) error {
	var err error
	if userID != "" {
		_, err = r.db.Exec(`DELETE FROM vault_entries WHERE user_id = ?`, userID)
	} else {
		_, err = r.db.Exec(`DELETE FROM vault_entries`)
	}
	if err != nil {
		return fmt.Errorf("failed to clear entries table: %w", err)
	}
	return nil
}

// CreateLog records an audit log entry.
func (r *SQLiteRepository) CreateLog(log *models.AuditLog) error {
	query := `INSERT INTO audit_logs (id, user_id, action, details, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := r.db.Exec(query, log.ID, log.UserID, log.Action, log.Details, log.Status, log.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}
	return nil
}

// ListLogs retrieves the most recent N audit log records for a UserID.
func (r *SQLiteRepository) ListLogs(userID string, limit int) ([]*models.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT id, user_id, action, details, status, timestamp FROM audit_logs WHERE user_id = ? OR user_id = '' ORDER BY timestamp DESC LIMIT ?`
	rows, err := r.db.Query(query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog
	for rows.Next() {
		var item models.AuditLog
		if err := rows.Scan(&item.ID, &item.UserID, &item.Action, &item.Details, &item.Status, &item.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan audit log row: %w", err)
		}
		logs = append(logs, &item)
	}

	return logs, nil
}
