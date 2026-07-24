package tests

import (
	"os"
	"path/filepath"
	"testing"

	"securevault/internal/models"
	"securevault/internal/service"
)

func TestFullVaultLifecycleIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "securevault_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test_vault.db")
	backupDir := filepath.Join(tempDir, "backups")

	// Set env config overrides for clean integration DB
	os.Setenv("SECUREVAULT_DATABASE_PATH", dbPath)
	os.Setenv("SECUREVAULT_BACKUP_DIR", backupDir)
	defer os.Unsetenv("SECUREVAULT_DATABASE_PATH")
	defer os.Unsetenv("SECUREVAULT_BACKUP_DIR")

	container, err := service.NewContainer("")
	if err != nil {
		t.Fatalf("failed initializing container: %v", err)
	}
	defer container.Close()

	user1Email := "user1@gmail.com"
	masterPass1 := "MasterPass123!"

	user2Email := "user2@gmail.com"
	masterPass2 := "MasterPass456!"

	// 1. Sign up User 1
	u1, err := container.AuthService.SignUp(user1Email, masterPass1)
	if err != nil || u1 == nil {
		t.Fatalf("failed signing up user 1: %v", err)
	}

	// 2. Add Vault Entry for User 1
	entry1 := &models.VaultEntry{
		Title:    "User 1 GitHub",
		Website:  "https://github.com",
		Username: "user1",
		Password: "User1SecretPassword123!",
		Category: "Dev",
		Tags:     []string{"git"},
		Favorite: true,
	}

	if err := container.VaultService.AddEntry(entry1); err != nil {
		t.Fatalf("failed adding entry for user 1: %v", err)
	}

	// 3. Verify User 1 can see their entry
	entries1, err := container.VaultService.ListEntries()
	if err != nil || len(entries1) != 1 {
		t.Fatalf("user 1 should have 1 entry, got %d", len(entries1))
	}

	// 4. Sign Out User 1 & Sign Up User 2
	container.AuthService.SignOut()
	u2, err := container.AuthService.SignUp(user2Email, masterPass2)
	if err != nil || u2 == nil {
		t.Fatalf("failed signing up user 2: %v", err)
	}

	// 5. Verify User 2's vault is empty and isolated from User 1
	entries2, err := container.VaultService.ListEntries()
	if err != nil || len(entries2) != 0 {
		t.Fatalf("user 2 vault must be empty (isolated from user 1), got %d entries", len(entries2))
	}

	// 6. Add entry for User 2
	entry2 := &models.VaultEntry{
		Title:    "User 2 Gmail",
		Website:  "https://gmail.com",
		Username: "user2",
		Password: "User2SecretPassword456!",
	}
	if err := container.VaultService.AddEntry(entry2); err != nil {
		t.Fatalf("failed adding entry for user 2: %v", err)
	}

	// 7. Sign Out User 2 & Sign back in as User 1
	container.AuthService.SignOut()
	_, _, err = container.AuthService.Login(user1Email, masterPass1)
	if err != nil {
		t.Fatalf("failed logging back in as user 1: %v", err)
	}

	// 8. Verify User 1 sees ONLY User 1's entries
	u1Entries, err := container.VaultService.ListEntries()
	if err != nil || len(u1Entries) != 1 || u1Entries[0].Title != "User 1 GitHub" {
		t.Fatalf("user 1 should only see user 1 entries after login")
	}
}
