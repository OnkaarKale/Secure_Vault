package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"securevault/internal/models"
)

func TestJSONExportAndImport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	jsonPath := filepath.Join(tempDir, "export.json")
	entries := []*models.VaultEntry{
		{ID: "e1", Title: "JSON Site", Username: "user1", Password: "p1", Category: "General", CreatedAt: time.Now().UTC()},
	}

	if err := ExportJSON(jsonPath, entries); err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}

	imported, err := ImportJSON(jsonPath)
	if err != nil || len(imported) != 1 {
		t.Fatalf("JSON import failed: %v", err)
	}

	if imported[0].Title != "JSON Site" {
		t.Errorf("imported title mismatch: got %s", imported[0].Title)
	}
}

func TestCSVExportAndImport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage_csv_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	csvPath := filepath.Join(tempDir, "export.csv")
	entries := []*models.VaultEntry{
		{ID: "e2", Title: "CSV Site", Website: "https://csv.com", Username: "user2", Password: "p2", Category: "Work", Tags: []string{"work", "tech"}, Favorite: true, CreatedAt: time.Now().UTC()},
	}

	if err := ExportCSV(csvPath, entries); err != nil {
		t.Fatalf("CSV export failed: %v", err)
	}

	imported, err := ImportCSV(csvPath)
	if err != nil || len(imported) != 1 {
		t.Fatalf("CSV import failed: %v", err)
	}

	if imported[0].Title != "CSV Site" {
		t.Errorf("imported title mismatch: got %s", imported[0].Title)
	}
}
