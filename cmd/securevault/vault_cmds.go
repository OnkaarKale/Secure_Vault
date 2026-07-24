package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"securevault/internal/clipboard"
	"securevault/internal/generator"
	"securevault/internal/models"
	"securevault/internal/ui"
)

var (
	showPasswords bool
	categoryFlag  string
	tagFlag       string
	favoriteFlag  bool
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage encrypted vault entries",
	Long:  `Perform CRUD operations, list, view, copy, and organize vault entries.`,
}

var vaultAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new encrypted entry to the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		title := ui.PromptString("Title (e.g. GitHub)", "")
		if title == "" {
			return fmt.Errorf("title cannot be empty")
		}

		website := ui.PromptString("Website URL", "")
		username := ui.PromptString("Username / Email", "")

		useGen := ui.PromptConfirm("Generate strong random password?")
		var password string
		var err error

		if useGen {
			password, err = generator.GeneratePassword(models.DefaultGeneratorOptions())
			if err != nil {
				return err
			}
			ui.PrintInfo("Generated Password: %s", password)
		} else {
			password, err = ui.PromptPassword("Enter Password: ")
			if err != nil {
				return err
			}
		}

		category := ui.PromptString("Category", "General")
		tagsInput := ui.PromptString("Tags (comma separated)", "")
		var tags []string
		if tagsInput != "" {
			for _, t := range parseTags(tagsInput) {
				tags = append(tags, t)
			}
		}
		notes := ui.PromptString("Notes", "")

		entry := &models.VaultEntry{
			Title:    title,
			Website:  website,
			Username: username,
			Password: password,
			Category: category,
			Tags:     tags,
			Notes:    notes,
			Favorite: false,
		}

		if err := container.VaultService.AddEntry(entry); err != nil {
			return err
		}

		ui.PrintSuccess("Entry '%s' added to vault successfully!", title)
		return nil
	},
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all vault entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		entries, err := container.VaultService.ListEntries()
		if err != nil {
			return err
		}

		filter := models.SearchFilter{
			Category:     categoryFlag,
			Tag:          tagFlag,
			FavoriteOnly: favoriteFlag,
		}

		filtered := container.SearchEngine.Filter(entries, filter)
		ui.RenderEntriesTable(filtered, showPasswords)
		return nil
	},
}

var vaultShowCmd = &cobra.Command{
	Use:   "show [id or title]",
	Short: "Show details of a specific entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		target := args[0]
		entry, err := findEntry(target)
		if err != nil {
			return err
		}

		ui.RenderEntryDetails(entry, true)
		return nil
	},
}

var vaultEditCmd = &cobra.Command{
	Use:   "edit [id or title]",
	Short: "Edit an existing vault entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		entry, err := findEntry(args[0])
		if err != nil {
			return err
		}

		ui.PrintInfo("Editing entry: %s", entry.Title)
		entry.Title = ui.PromptString("Title", entry.Title)
		entry.Website = ui.PromptString("Website", entry.Website)
		entry.Username = ui.PromptString("Username", entry.Username)

		if ui.PromptConfirm("Update password?") {
			if ui.PromptConfirm("Generate random password?") {
				genPass, err := generator.GeneratePassword(models.DefaultGeneratorOptions())
				if err != nil {
					return err
				}
				entry.Password = genPass
				ui.PrintInfo("Generated Password: %s", genPass)
			} else {
				newP, err := ui.PromptPassword("New Password: ")
				if err != nil {
					return err
				}
				entry.Password = newP
			}
		}

		entry.Category = ui.PromptString("Category", entry.Category)
		entry.Notes = ui.PromptString("Notes", entry.Notes)

		if err := container.VaultService.UpdateEntry(entry); err != nil {
			return err
		}

		ui.PrintSuccess("Entry '%s' updated successfully!", entry.Title)
		return nil
	},
}

var vaultDeleteCmd = &cobra.Command{
	Use:   "delete [id or title]",
	Short: "Delete an entry from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		entry, err := findEntry(args[0])
		if err != nil {
			return err
		}

		if !ui.PromptConfirm(fmt.Sprintf("Are you sure you want to delete '%s'?", entry.Title)) {
			ui.PrintInfo("Delete operation cancelled.")
			return nil
		}

		if err := container.VaultService.DeleteEntry(entry.ID); err != nil {
			return err
		}

		ui.PrintSuccess("Entry '%s' deleted from vault.", entry.Title)
		return nil
	},
}

var vaultCopyCmd = &cobra.Command{
	Use:   "copy [id or title]",
	Short: "Copy password to system clipboard with auto-clear background timer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		entry, err := findEntry(args[0])
		if err != nil {
			return err
		}

		timeout := container.Config.ClipboardTimeoutSec
		if err := clipboard.WriteAndAutoClear(entry.Password, timeout); err != nil {
			return err
		}

		ui.PrintSuccess("Password for '%s' copied to clipboard! (Will auto-clear in %d seconds)", entry.Title, timeout)
		return nil
	},
}

var vaultFavCmd = &cobra.Command{
	Use:   "favorite [id or title]",
	Short: "Toggle favorite status for an entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		entry, err := findEntry(args[0])
		if err != nil {
			return err
		}

		newFav, err := container.VaultService.ToggleFavorite(entry.ID)
		if err != nil {
			return err
		}

		if newFav {
			ui.PrintSuccess("Entry '%s' marked as favorite ★", entry.Title)
		} else {
			ui.PrintInfo("Entry '%s' removed from favorites", entry.Title)
		}
		return nil
	},
}

func ensureUnlocked() error {
	if container.SessionManager.IsUnlocked() {
		return nil
	}

	init, err := container.AuthService.IsInitialized()
	if err != nil || !init {
		return fmt.Errorf("vault is not initialized. Run 'securevault init' first")
	}

	pass, err := ui.PromptPassword("Enter Master Password to unlock: ")
	if err != nil {
		return err
	}

	_, err = container.AuthService.Authenticate(pass)
	return err
}

func findEntry(query string) (*models.VaultEntry, error) {
	entries, err := container.VaultService.ListEntries()
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if e.ID == query || e.Title == query {
			return e, nil
		}
	}

	// Partial match search fallback
	filtered := container.SearchEngine.Filter(entries, models.SearchFilter{Query: query})
	if len(filtered) == 1 {
		return filtered[0], nil
	}
	if len(filtered) > 1 {
		return nil, fmt.Errorf("multiple entries found for '%s'. Please specify exact ID", query)
	}

	return nil, fmt.Errorf("entry '%s' not found", query)
}

func parseTags(input string) []string {
	var tags []string
	for _, part := range strings.Split(input, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	return tags
}

func init() {
	vaultListCmd.Flags().BoolVarP(&showPasswords, "show-passwords", "p", false, "display plain-text passwords in list")
	vaultListCmd.Flags().StringVarP(&categoryFlag, "category", "c", "", "filter entries by category")
	vaultListCmd.Flags().StringVarP(&tagFlag, "tag", "t", "", "filter entries by tag")
	vaultListCmd.Flags().BoolVarP(&favoriteFlag, "favorite", "f", false, "filter only favorite entries")

	vaultCmd.AddCommand(vaultAddCmd)
	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultShowCmd)
	vaultCmd.AddCommand(vaultEditCmd)
	vaultCmd.AddCommand(vaultDeleteCmd)
	vaultCmd.AddCommand(vaultCopyCmd)
	vaultCmd.AddCommand(vaultFavCmd)

	rootCmd.AddCommand(vaultCmd)
}
