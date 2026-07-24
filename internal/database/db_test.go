package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestInitDBAndWithTx(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "db_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("failed initializing DB: %v", err)
	}
	defer db.Close()

	err = WithTx(db, func(tx *sql.Tx) error {
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx failed: %v", err)
	}
}
