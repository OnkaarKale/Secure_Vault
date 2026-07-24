package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"securevault/internal/clipboard"
	"securevault/internal/generator"
	"securevault/internal/models"
	"securevault/internal/storage"
	"securevault/internal/ui"
	"securevault/internal/utils"
)

var interactiveCmd = &cobra.Command{
	Use:   "menu",
	Short: "Launch interactive menu mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunInteractiveMenu()
	},
}

func RunInteractiveMenu() error {
	for {
		ui.PrintBanner()

		currUser := container.SessionManager.GetCurrentUser()
		isUnlocked := container.SessionManager.IsUnlocked()

		if isUnlocked && currUser != nil {
			ui.PrintSuccess("Session Active: Signed in as [%s]", currUser.Email)
		} else {
			ui.PrintWarning("Session Locked: Sign in or Register to access your vault")
		}

		fmt.Println(ui.Bold("\n=================== INTERACTIVE MENU ==================="))
		if !isUnlocked {
			fmt.Println("  1. 🔑 Sign In / Log In to Vault")
			fmt.Println("  2. 📝 Sign Up / Register New User Account")
			fmt.Println("  3. 🎲 Password & Passphrase CSPRNG Generator")
			fmt.Println("  4. 📊 Check Vault Status & Registered Users")
			fmt.Println("  0. 🚪 Exit")
		} else {
			fmt.Println("  1. 📋 List All Entries & Sequential Copy")
			fmt.Println("  2. ➕ Add New Vault Entry")
			fmt.Println("  3. 🔍 Search Vault Entries (Includes Favorites ★ Filter)")
			fmt.Println("  4. ✏️  Edit / Update Vault Entry")
			fmt.Println("  5. 🗑️  Delete Vault Entry")
			fmt.Println("  6. ★  Toggle Favorite Star")
			fmt.Println("  7. 🎲 Password & Passphrase CSPRNG Generator")
			fmt.Println("  8. 🛡️  Run Security Audit Scan & Payload MAC Check")
			fmt.Println("  9. 💾 Backup & Restore Snapshots (.svb)")
			fmt.Println(" 10. 📤 Export & Import Data (JSON / CSV)")
			fmt.Println(" 11. 🔑 Change Master Password")
			fmt.Println(" 12. 📊 Check Vault Status & Registered Users")
			fmt.Println(" 13. 🔒 Sign Out / Lock Session")
			fmt.Println(" 14. 🧹 Clear System Clipboard Immediately")
			fmt.Println("  0. 🚪 Exit")
		}
		fmt.Println(ui.Bold("========================================================\n"))

		choice := ui.PromptString("Select an option number", "1")

		if !isUnlocked {
			switch choice {
			case "1":
				_ = handleLogin()
			case "2":
				_ = handleSignUp()
			case "3":
				handleGeneratorSubmenu()
			case "4":
				handleStatusDisplay()
			case "0", "exit", "q", "quit":
				ui.PrintInfo("Goodbye!")
				return nil
			default:
				ui.PrintError("Invalid option selected. Please choose a valid number.")
			}
		} else {
			switch choice {
			case "1":
				handleListAndCopy()
			case "2":
				handleAddEntry()
			case "3":
				handleSearchEntries()
			case "4":
				handleEditEntry()
			case "5":
				handleDeleteEntry()
			case "6":
				handleToggleFavorite()
			case "7":
				handleGeneratorSubmenu()
			case "8":
				handleAuditScan()
			case "9":
				handleBackupSubmenu()
			case "10":
				handleImportExportSubmenu()
			case "11":
				handleChangeMasterPassword()
			case "12":
				handleStatusDisplay()
			case "13":
				container.AuthService.SignOut()
				ui.PrintSuccess("Signed out. Vault session locked and encryption keys wiped.")
			case "14":
				_ = clipboard.Clear()
				ui.PrintSuccess("System clipboard purged immediately.")
			case "0", "exit", "q", "quit":
				ui.PrintInfo("Goodbye!")
				return nil
			default:
				ui.PrintError("Invalid option selected. Please choose a valid number.")
			}
		}

		fmt.Println()
		ui.PromptString("Press ENTER to return to menu...", "")
	}
}

func handleLogin() error {
	email, err := ui.PromptInput("Enter Email / Gmail Username: ")
	if err != nil {
		return err
	}
	pass, err := ui.PromptPassword("Enter Master Password: ")
	if err != nil {
		return err
	}
	ui.ShowSpinner("Verifying Argon2id key derivation...", 500)
	_, _, err = container.AuthService.Login(email, pass)
	if err != nil {
		ui.PrintError("Login failed: %v", err)
		return err
	}
	ui.PrintSuccess("Authentication successful! Vault unlocked for '%s'.", email)
	return nil
}

func handleSignUp() error {
	email, err := ui.PromptInput("Enter Email / Gmail Username: ")
	if err != nil {
		return err
	}
	pass1, err := ui.PromptPassword("Enter Master Password: ")
	if err != nil {
		return err
	}
	if len(pass1) < 8 {
		ui.PrintError("Master password must be at least 8 characters long.")
		return fmt.Errorf("password too short")
	}
	pass2, err := ui.PromptPassword("Confirm Master Password: ")
	if err != nil {
		return err
	}
	if pass1 != pass2 {
		ui.PrintError("Passwords do not match.")
		return fmt.Errorf("passwords do not match")
	}

	ui.ShowSpinner("Deriving Argon2id key and initializing vault...", 500)
	_, err = container.AuthService.SignUp(email, pass1)
	if err != nil {
		ui.PrintError("Signup failed: %v", err)
		return err
	}
	ui.PrintSuccess("Account created successfully for '%s'! Session unlocked.", email)
	return nil
}

// findEntryInList resolves an entry from a slice using 1-based index (#1), short ID prefix (e.g. 5bc989ec), or Title.
func findEntryInList(entries []*models.VaultEntry, query string) *models.VaultEntry {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return nil
	}

	if idx, err := strconv.Atoi(trimmed); err == nil && idx >= 1 && idx <= len(entries) {
		return entries[idx-1]
	}

	qLower := strings.ToLower(trimmed)
	for _, e := range entries {
		eIDLower := strings.ToLower(e.ID)
		if eIDLower == qLower || strings.HasPrefix(eIDLower, qLower) || strings.EqualFold(e.Title, trimmed) {
			return e
		}
	}

	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Title), qLower) {
			return e
		}
	}

	return nil
}

func copyPasswordWithFallback(entry *models.VaultEntry) {
	timeout := container.Config.ClipboardTimeoutSec
	if err := clipboard.WriteAndAutoClear(entry.Password, timeout); err != nil {
		ui.PrintWarning("System clipboard unavailable on this terminal.")
		ui.PrintSuccess("Decrypted Password for '%s': %s", entry.Title, ui.Magenta(entry.Password))
		return
	}
	ui.PrintSuccess("Copied password for '%s' to clipboard! (Auto-clears in %ds)", entry.Title, timeout)
}

// handleSequentialCopy handles site URL -> Username -> Password copying with previous field replacement warnings.
func handleSequentialCopy(target *models.VaultEntry) {
	fmt.Println(ui.Bold(fmt.Sprintf("\n--- Sequential Copy Workflow for '%s' ---", target.Title)))

	// 1. Website URL
	if target.Website != "" {
		if ui.PromptConfirm("Copy Website URL to clipboard? [" + target.Website + "]") {
			if err := clipboard.WriteAndAutoClear(target.Website, container.Config.ClipboardTimeoutSec); err != nil {
				ui.PrintInfo("Website: %s", target.Website)
			} else {
				ui.PrintSuccess("Copied Website URL to clipboard!")
			}
		}
	}

	// 2. Username
	if target.Username != "" {
		ui.PrintWarning("⚠️ Note: Copying username will replace previous clipboard content!")
		if ui.PromptConfirm("Copy Username to clipboard? [" + target.Username + "]") {
			if err := clipboard.WriteAndAutoClear(target.Username, container.Config.ClipboardTimeoutSec); err != nil {
				ui.PrintInfo("Username: %s", target.Username)
			} else {
				ui.PrintSuccess("Copied Username to clipboard!")
			}
		}
	}

	// 3. Password
	ui.PrintWarning("⚠️ Note: Copying password will replace previous clipboard content (auto-clears in 30s)!")
	if ui.PromptConfirm("Copy Password to clipboard?") {
		copyPasswordWithFallback(target)
	}
}

func handleListAndCopy() {
	entries, err := container.VaultService.ListEntries()
	if err != nil {
		ui.PrintError("%v", err)
		return
	}

	if len(entries) == 0 {
		ui.PrintWarning("Vault is currently empty. Use Option 2 to add a new entry.")
		return
	}

	ui.RenderEntriesTable(entries, false)

	fmt.Println(ui.Bold("\n--- Actions ---"))
	fmt.Println(" Enter Entry # (e.g. 1) or ID (e.g. 5bc989ec) to copy/inspect | [ENTER] Return to Menu")
	choice := ui.PromptString("Select Entry # or ID", "")
	if choice == "" {
		return
	}

	target := findEntryInList(entries, choice)
	if target == nil {
		ui.PrintError("Entry '%s' not found.", choice)
		return
	}

	if ui.PromptConfirm(fmt.Sprintf("Inspect full details for '%s'?", target.Title)) {
		ui.RenderEntryDetails(target, false)
		if ui.PromptConfirm("Reveal plaintext password?") {
			ui.PrintSuccess("Password: %s", ui.Magenta(target.Password))
		}
	}

	handleSequentialCopy(target)
}

func handleAddEntry() {
	fmt.Println(ui.Bold("\n--- Add New Vault Entry ---"))
	title := ui.PromptString("Title (required)", "")
	if strings.TrimSpace(title) == "" {
		ui.PrintError("Title is required.")
		return
	}

	website := ui.PromptString("Website URL", "")
	username := ui.PromptString("Username / Email", "")

	var password string
	if ui.PromptConfirm("Generate random secure password?") {
		genPass, err := generator.GeneratePassword(models.DefaultGeneratorOptions())
		if err == nil {
			password = genPass
			ui.PrintInfo("Generated Password: %s", ui.Magenta(password))
		}
	}

	if password == "" {
		p, err := ui.PromptPassword("Password: ")
		if err != nil {
			ui.PrintError("%v", err)
			return
		}
		password = p
	}

	category := ui.PromptString("Category", "General")
	notes := ui.PromptString("Notes", "")
	tagsInput := ui.PromptString("Tags (comma-separated)", "")

	var tags []string
	if tagsInput != "" {
		for _, t := range strings.Split(tagsInput, ",") {
			if trimmed := strings.TrimSpace(t); trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}

	favorite := ui.PromptConfirm("Mark as favorite ★?")

	entry := &models.VaultEntry{
		Title:    title,
		Website:  website,
		Username: username,
		Password: password,
		Category: category,
		Notes:    notes,
		Tags:     tags,
		Favorite: favorite,
	}

	ui.ShowSpinner("Encrypting and saving entry...", 500)
	if err := container.VaultService.AddEntry(entry); err != nil {
		ui.PrintError("Failed adding entry: %v", err)
		return
	}

	ui.PrintSuccess("Entry '%s' added successfully!", title)
}

func handleSearchEntries() {
	for {
		fmt.Println(ui.Bold("\n--- Search Options ---"))
		fmt.Println("  1. Search All Entries (By Query)")
		fmt.Println("  2. Filter Favorites Only ★")
		fmt.Println("  3. Return to Menu")
		mode := ui.PromptString("Select search mode", "1")

		if mode == "3" {
			return
		}

		var filter models.SearchFilter
		if mode == "2" {
			filter.FavoriteOnly = true
			query := ui.PromptString("Optional search term (or press ENTER for all favorites)", "")
			filter.Query = query
		} else {
			query := ui.PromptString("Enter search query (title, website, username, category, tag)", "")
			if strings.TrimSpace(query) == "" {
				return
			}
			filter.Query = query
		}

		entries, err := container.VaultService.ListEntries()
		if err != nil {
			ui.PrintError("Failed listing entries: %v", err)
			return
		}

		results := container.SearchEngine.Filter(entries, filter)
		if len(results) == 0 {
			if filter.FavoriteOnly {
				ui.PrintWarning("No favorite entries found ★.")
			} else {
				ui.PrintWarning("No matching entries found for query.")
			}
			continue
		}

		ui.PrintSuccess("Found %d matching entries:", len(results))
		ui.RenderEntriesTable(results, false)

		choice := ui.PromptString("Enter Entry # or ID for copy / details (or ENTER to search again)", "")
		if choice != "" {
			target := findEntryInList(results, choice)
			if target != nil {
				if ui.PromptConfirm(fmt.Sprintf("Inspect full details for '%s'?", target.Title)) {
					ui.RenderEntryDetails(target, false)
					if ui.PromptConfirm("Reveal plaintext password?") {
						ui.PrintSuccess("Password: %s", ui.Magenta(target.Password))
					}
				}
				handleSequentialCopy(target)
			} else {
				ui.PrintError("Selected entry not found.")
			}
		}
		break
	}
}

func handleEditEntry() {
	entries, err := container.VaultService.ListEntries()
	if err != nil || len(entries) == 0 {
		ui.PrintWarning("No entries available to edit.")
		return
	}

	ui.RenderEntriesTable(entries, false)
	id := ui.PromptString("Enter Entry ID or # to edit", "")
	if id == "" {
		return
	}

	entry := findEntryInList(entries, id)
	if entry == nil {
		ui.PrintError("Entry '%s' not found.", id)
		return
	}

	ui.PrintInfo("Editing entry: %s", entry.Title)
	entry.Title = ui.PromptString("Title", entry.Title)
	entry.Website = ui.PromptString("Website", entry.Website)
	entry.Username = ui.PromptString("Username", entry.Username)

	if ui.PromptConfirm("Update password?") {
		if ui.PromptConfirm("Generate random password?") {
			genPass, err := generator.GeneratePassword(models.DefaultGeneratorOptions())
			if err == nil {
				entry.Password = genPass
				ui.PrintInfo("Generated Password: %s", genPass)
			}
		} else {
			newP, err := ui.PromptPassword("New Password: ")
			if err == nil {
				entry.Password = newP
			}
		}
	}

	entry.Category = ui.PromptString("Category", entry.Category)
	entry.Notes = ui.PromptString("Notes", entry.Notes)

	ui.ShowSpinner("Re-encrypting and updating entry...", 500)
	if err := container.VaultService.UpdateEntry(entry); err != nil {
		ui.PrintError("Failed updating entry: %v", err)
		return
	}

	ui.PrintSuccess("Entry '%s' updated successfully!", entry.Title)
}

func handleDeleteEntry() {
	entries, err := container.VaultService.ListEntries()
	if err != nil || len(entries) == 0 {
		ui.PrintWarning("No entries available to delete.")
		return
	}

	ui.RenderEntriesTable(entries, false)
	id := ui.PromptString("Enter Entry ID or # to delete", "")
	if id == "" {
		return
	}

	entry := findEntryInList(entries, id)
	if entry == nil {
		ui.PrintError("Entry '%s' not found.", id)
		return
	}

	if !ui.PromptConfirm(fmt.Sprintf("Are you sure you want to delete '%s'?", entry.Title)) {
		ui.PrintInfo("Delete cancelled.")
		return
	}

	if err := container.VaultService.DeleteEntry(entry.ID); err != nil {
		ui.PrintError("Delete error: %v", err)
		return
	}

	ui.PrintSuccess("Entry '%s' deleted successfully!", entry.Title)
}

func handleToggleFavorite() {
	entries, err := container.VaultService.ListEntries()
	if err != nil || len(entries) == 0 {
		ui.PrintWarning("No entries available.")
		return
	}

	ui.RenderEntriesTable(entries, false)
	id := ui.PromptString("Enter Entry ID or # to toggle favorite star", "")
	if id == "" {
		return
	}

	entry := findEntryInList(entries, id)
	if entry == nil {
		ui.PrintError("Entry '%s' not found.", id)
		return
	}

	fav, err := container.VaultService.ToggleFavorite(entry.ID)
	if err != nil {
		ui.PrintError("%v", err)
		return
	}

	if fav {
		ui.PrintSuccess("Marked entry '%s' as favorite ★", entry.Title)
	} else {
		ui.PrintInfo("Removed entry '%s' from favorites.", entry.Title)
	}
}

func handleGeneratorSubmenu() {
	fmt.Println(ui.Bold("\n--- CSPRNG Generator Submenu ---"))
	fmt.Println("  1. Generate Secure Password")
	fmt.Println("  2. Generate Word Passphrase")
	fmt.Println("  3. Generate Random Username")
	fmt.Println("  4. Evaluate Password Strength & Entropy")
	ch := ui.PromptString("Select option", "1")

	switch ch {
	case "1":
		opts := models.DefaultGeneratorOptions()
		pass, err := generator.GeneratePassword(opts)
		if err != nil {
			ui.PrintError("%v", err)
			return
		}
		entropy := utils.CalculateEntropy(pass)
		ui.PrintSuccess("Generated Password: %s", ui.Magenta(pass))
		fmt.Printf(" Length: %d | Entropy: %.2f bits\n", len(pass), entropy)

		if ui.PromptConfirm("Copy generated password to clipboard?") {
			fakeEntry := &models.VaultEntry{Title: "Generated Password", Password: pass}
			copyPasswordWithFallback(fakeEntry)
		}
	case "2":
		opts := models.DefaultPassphraseOptions()
		phrase, err := generator.GeneratePassphrase(opts)
		if err != nil {
			ui.PrintError("%v", err)
			return
		}
		entropy := utils.CalculateEntropy(phrase)
		ui.PrintSuccess("Generated Passphrase: %s", ui.Magenta(phrase))
		fmt.Printf(" Entropy: %.2f bits\n", entropy)

		if ui.PromptConfirm("Copy generated passphrase to clipboard?") {
			fakeEntry := &models.VaultEntry{Title: "Generated Passphrase", Password: phrase}
			copyPasswordWithFallback(fakeEntry)
		}
	case "3":
		uname, err := generator.GenerateUsername()
		if err != nil {
			ui.PrintError("%v", err)
			return
		}
		ui.PrintSuccess("Generated Username: %s", ui.Cyan(uname))
	case "4":
		target := ui.PromptString("Enter password to analyze", "")
		if target != "" {
			st := generator.EvaluateStrength(target)
			fmt.Printf(" Rating : %s | Score: %d/4 | Entropy: %.2f bits\n", ui.Magenta(st.Rating), st.Score, st.Entropy)
		}
	}
}

func handleAuditScan() {
	ui.ShowSpinner("Verifying AES-256-GCM authentication tags and auditing passwords...", 800)
	if err := container.VaultService.VerifyIntegrity(); err != nil {
		ui.PrintError("Integrity Verification Failed: %v", err)
		return
	}

	report, err := container.VaultService.AuditSecurity()
	if err != nil {
		ui.PrintError("Audit failed: %v", err)
		return
	}

	fmt.Println(ui.Bold("\n--- Security Audit Report ---"))
	fmt.Printf(" Total Entries Analyzed : %d\n", report.TotalEntries)
	fmt.Printf(" Vault Health Score     : %s / 100\n", ui.Green("%d", report.Score))
	fmt.Printf(" Weak Passwords Found   : %d\n", len(report.WeakPasswords))
	fmt.Printf(" Duplicate Passwords    : %d\n", len(report.DuplicatePasswords))
	fmt.Printf(" Passwords > 90 Days    : %d\n", len(report.OldPasswords))

	if len(report.WeakPasswords) > 0 {
		ui.PrintWarning(" Weak Passwords detected in:")
		for _, w := range report.WeakPasswords {
			fmt.Printf("   • %s (%s)\n", w.Title, w.Username)
		}
	}

	if len(report.DuplicatePasswords) > 0 {
		ui.PrintWarning(" Duplicate Passwords re-used across:")
		for _, titles := range report.DuplicatePasswords {
			fmt.Printf("   • %s\n", strings.Join(titles, ", "))
		}
	}
	fmt.Println(ui.Bold("-----------------------------\n"))
}

func handleBackupSubmenu() {
	fmt.Println(ui.Bold("\n--- Backup & Restore Submenu ---"))
	fmt.Println("  1. Create Encrypted Snapshot (.svb)")
	fmt.Println("  2. Restore Vault from Snapshot")
	ch := ui.PromptString("Select option", "1")

	switch ch {
	case "1":
		dest := ui.PromptString("Enter destination directory or file path for backup [. /backups]", "./backups")
		ui.ShowSpinner("Creating encrypted backup snapshot...", 500)
		bmeta, err := container.BackupService.CreateBackupToPath(dest)
		if err != nil {
			ui.PrintError("Backup failed: %v", err)
			return
		}
		ui.PrintSuccess("Backup snapshot created successfully!")
		fmt.Printf(" File Path : %s\n", bmeta.FilePath)
		fmt.Printf(" Checksum  : %s\n", bmeta.Checksum)
	case "2":
		backups, err := container.BackupService.ListBackups()
		if err != nil || len(backups) == 0 {
			ui.PrintWarning("No backup snapshots in default directory. You can also type a custom file path.")
		} else {
			ui.PrintInfo("Available Backup Snapshots:")
			for idx, b := range backups {
				fmt.Printf(" [%d] %s (%s)\n", idx+1, b.FilePath, utils.FormatTime(b.Timestamp))
			}
		}

		path := ui.PromptString("Enter Backup File Path or # to restore", "")
		if path != "" {
			cleanPath := strings.TrimPrefix(strings.TrimSpace(path), "#")
			cleanPath = strings.TrimSpace(cleanPath)
			if idx, err := strconv.Atoi(cleanPath); err == nil && len(backups) > 0 && idx >= 1 && idx <= len(backups) {
				path = backups[idx-1].FilePath
			}

			if _, err := os.Stat(path); err != nil {
				ui.PrintError("Backup snapshot file '%s' not found.", path)
				return
			}

			pkg, err := container.BackupService.InspectBackup(path)
			if err != nil {
				ui.PrintError("Failed reading snapshot header: %v", err)
				return
			}

			fmt.Println(ui.Bold("\n------------------- BACKUP SNAPSHOT DETAILS -------------------"))
			fmt.Printf(" File Name   : %s\n", filepath.Base(path))
			fmt.Printf(" Full Path   : %s\n", path)
			fmt.Printf(" Timestamp   : %s UTC\n", utils.FormatTime(pkg.Timestamp))
			fmt.Printf(" Records     : %d entries\n", len(pkg.Entries))
			fmt.Printf(" Version     : %s\n", pkg.Version)
			fmt.Println(ui.Bold("---------------------------------------------------------------"))

			ui.PrintWarning("⚠️ WARNING: Restoring will OVERWRITE and REPLACE ALL current vault entries!")
			ui.PrintWarning("⚠️ Remember: Ensure your current entries are backed up before proceeding.")

			if ui.PromptConfirm("Are you SURE you want to restore this backup taken on " + utils.FormatTime(pkg.Timestamp) + "?") {
				ui.ShowSpinner("Restoring backup and re-encrypting records...", 800)
				if err := container.BackupService.RestoreBackup(path); err != nil {
					ui.PrintError("Restore failed: %v", err)
				} else {
					ui.PrintSuccess("Vault successfully restored from snapshot!")
				}
			}
		}
	}
}

func handleImportExportSubmenu() {
	entries, err := container.VaultService.ListEntries()
	if err != nil {
		ui.PrintError("%v", err)
		return
	}

	fmt.Println(ui.Bold("\n--- Import & Export Submenu ---"))
	fmt.Println("  1. Export Vault Entries (JSON)")
	fmt.Println("  2. Export Vault Entries (CSV)")
	fmt.Println("  3. Import Vault Entries (JSON or CSV)")
	ch := ui.PromptString("Select option", "1")

	switch ch {
	case "1":
		outPath := ui.PromptString("Export output path", "./vault_export.json")
		if err := storage.ExportJSON(outPath, entries); err != nil {
			ui.PrintError("Export error: %v", err)
		} else {
			ui.PrintSuccess("Successfully exported vault entries to %s", outPath)
		}
	case "2":
		outPath := ui.PromptString("Export output path", "./vault_export.csv")
		if err := storage.ExportCSV(outPath, entries); err != nil {
			ui.PrintError("Export error: %v", err)
		} else {
			ui.PrintSuccess("Successfully exported vault entries to %s", outPath)
		}
	case "3":
		inPath := ui.PromptString("Import file path (JSON or CSV)", "")
		if inPath != "" {
			var imported []*models.VaultEntry
			var err error
			if strings.HasSuffix(inPath, ".csv") {
				imported, err = storage.ImportCSV(inPath)
			} else {
				imported, err = storage.ImportJSON(inPath)
			}
			if err != nil {
				ui.PrintError("Import error: %v", err)
				return
			}
			for _, entry := range imported {
				_ = container.VaultService.AddEntry(entry)
			}
			ui.PrintSuccess("Successfully imported %d entries into your vault!", len(imported))
		}
	}
}

func handleChangeMasterPassword() {
	currPass, err := ui.PromptPassword("Enter Current Master Password: ")
	if err != nil {
		return
	}

	newPass1, err := ui.PromptPassword("Enter New Master Password: ")
	if err != nil {
		return
	}
	if len(newPass1) < 8 {
		ui.PrintError("New password must be at least 8 characters long.")
		return
	}

	newPass2, err := ui.PromptPassword("Confirm New Master Password: ")
	if err != nil {
		return
	}
	if newPass1 != newPass2 {
		ui.PrintError("Passwords do not match.")
		return
	}

	ui.ShowSpinner("Re-encrypting all entries with new master key...", 1000)
	if err := container.AuthService.ChangeMasterPassword(currPass, newPass1); err != nil {
		ui.PrintError("Failed changing password: %v", err)
		return
	}

	ui.PrintSuccess("Master password changed and all entries re-encrypted under new salt!")
}

func handleStatusDisplay() {
	init, err := container.AuthService.IsInitialized()
	if err != nil {
		ui.PrintError("%v", err)
		return
	}

	fmt.Println(ui.Bold("\n--- Vault Status & Database ---"))
	if !init {
		ui.PrintWarning("Status: Uninitialized (0 registered users)")
		return
	}

	if container.SessionManager.IsUnlocked() {
		ui.PrintSuccess("Status: UNLOCKED (Active session)")
		currUser := container.SessionManager.GetCurrentUser()
		if currUser != nil {
			fmt.Printf(" Active User     : %s\n", currUser.Email)
		}
	} else {
		ui.PrintWarning("Status: LOCKED")
	}

	userCount, _ := container.UserRepo.CountUsers()
	fmt.Printf(" Registered Users: %d\n", userCount)
	fmt.Printf(" Database Path   : %s\n", container.Config.DatabasePath)
	fmt.Printf(" Backup Dir      : %s\n", container.Config.BackupDir)
	fmt.Println(ui.Bold("---------------------------------\n"))
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}
