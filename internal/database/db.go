// Package database handles SQLite database initialization, schema migration, and transaction execution.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// InitDB connects to the SQLite database, configures pragmas, and creates required table schemas.
func InitDB(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Connect with WAL mode and foreign keys enabled
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=ON&_busy_timeout=5000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite single writer guarantee

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	if err := createSchemas(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

func createSchemas(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			master_hash TEXT NOT NULL,
			master_salt BLOB NOT NULL,
			argon2_params TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,

		`CREATE TABLE IF NOT EXISTS vault_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			vault_id TEXT NOT NULL,
			initialized INTEGER NOT NULL DEFAULT 0,
			master_hash TEXT NOT NULL,
			master_salt BLOB NOT NULL,
			argon2_params TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS vault_entries (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL,
			website TEXT,
			username TEXT,
			encrypted_payload BLOB NOT NULL,
			category TEXT NOT NULL DEFAULT 'General',
			tags TEXT NOT NULL DEFAULT '',
			favorite INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_entries_user_id ON vault_entries(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_entries_title ON vault_entries(title);`,
		`CREATE INDEX IF NOT EXISTS idx_entries_category ON vault_entries(category);`,
		`CREATE INDEX IF NOT EXISTS idx_entries_favorite ON vault_entries(favorite);`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			details TEXT NOT NULL,
			status TEXT NOT NULL,
			timestamp TIMESTAMP NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// WithTx executes the given function within a database transaction.
func WithTx(db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
