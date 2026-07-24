package repository

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"securevault/internal/database"
	"securevault/internal/models"
)

func TestSQLiteRepository(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "repo_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test_repo.db")
	db, err := database.InitDB(dbPath)
	if err != nil {
		t.Fatalf("failed init db: %v", err)
	}
	defer db.Close()

	repo := NewSQLiteRepository(db)

	userID := "u-1"

	// Test Metadata
	meta := &models.VaultMetadata{
		VaultID:      "v-123",
		Initialized:  true,
		MasterHash:   "abcd",
		MasterSalt:   []byte("salt"),
		Argon2Params: models.DefaultArgon2Params(),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := repo.SaveMetadata(meta); err != nil {
		t.Fatalf("failed saving metadata: %v", err)
	}

	gotMeta, err := repo.GetMetadata()
	if err != nil || gotMeta == nil || !gotMeta.Initialized {
		t.Fatalf("failed retrieving metadata: %v", err)
	}

	// Test Entry Operations
	entry := &EntryRow{
		ID:               "e-1",
		UserID:           userID,
		Title:            "Test Entry",
		Website:          "https://test.com",
		Username:         "user1",
		EncryptedPayload: []byte(`{"data":"secret"}`),
		Category:         "General",
		Tags:             "test,unit",
		Favorite:         false,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	if err := repo.CreateEntry(entry); err != nil {
		t.Fatalf("failed creating entry: %v", err)
	}

	gotEntry, err := repo.GetEntryByID(userID, "e-1")
	if err != nil || gotEntry.Title != "Test Entry" {
		t.Fatalf("failed fetching entry: %v", err)
	}

	entries, err := repo.ListEntries(userID)
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed listing entries: %v", err)
	}

	if err := repo.ToggleFavorite(userID, "e-1", true); err != nil {
		t.Fatalf("failed toggling favorite: %v", err)
	}

	if err := repo.DeleteEntry(userID, "e-1"); err != nil {
		t.Fatalf("failed deleting entry: %v", err)
	}

	// Test Audit Logs
	logItem := &models.AuditLog{
		ID:        "l-1",
		UserID:    userID,
		Action:    "TEST",
		Details:   "Unit test audit",
		Status:    "SUCCESS",
		Timestamp: time.Now().UTC(),
	}
	if err := repo.CreateLog(logItem); err != nil {
		t.Fatalf("failed creating audit log: %v", err)
	}

	logs, err := repo.ListLogs(userID, 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("failed listing audit logs: %v", err)
	}
}
