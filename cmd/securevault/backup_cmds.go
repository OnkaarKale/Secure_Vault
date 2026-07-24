package main

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"securevault/internal/ui"
	"securevault/internal/utils"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Manage encrypted vault backups and restoration",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an encrypted backup snapshot of your vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		ui.ShowSpinner("Encrypting and saving backup snapshot...", 600)

		bmeta, err := container.BackupService.CreateBackup()
		if err != nil {
			return err
		}

		ui.PrintSuccess("Backup created successfully!")
		fmt.Printf(" File Path: %s\n", bmeta.FilePath)
		fmt.Printf(" Entries  : %d\n", bmeta.EntryCount)
		fmt.Printf(" Checksum : %s\n", bmeta.Checksum)
		return nil
	},
}

var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List existing backup snapshots",
	RunE: func(cmd *cobra.Command, args []string) error {
		backups, err := container.BackupService.ListBackups()
		if err != nil {
			return err
		}

		if len(backups) == 0 {
			ui.PrintWarning("No backup files found in %s", container.Config.BackupDir)
			return nil
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Filename", "Created", "Checksum"})
		table.SetBorder(true)

		for _, b := range backups {
			table.Append([]string{
				b.ID,
				utils.FormatTime(b.Timestamp),
				b.Checksum[:12] + "...",
			})
		}

		table.Render()
		return nil
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore [backup-file-path]",
	Short: "Restore vault entries from an encrypted backup snapshot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		filePath := args[0]
		if !ui.PromptConfirm("WARNING: Restoring backup will replace current vault entries. Proceed?") {
			ui.PrintInfo("Restore cancelled.")
			return nil
		}

		ui.ShowSpinner("Decrypting and restoring vault state...", 800)

		if err := container.BackupService.RestoreBackup(filePath); err != nil {
			return err
		}

		ui.PrintSuccess("Vault successfully restored from %s", filePath)
		return nil
	},
}

func init() {
	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupRestoreCmd)

	rootCmd.AddCommand(backupCmd)
}
