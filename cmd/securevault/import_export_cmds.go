package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"securevault/internal/models"
	"securevault/internal/storage"
	"securevault/internal/ui"
)

var (
	exportFormat string
	exportFile   string
	importFormat string
	importFile   string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export vault entries to JSON or CSV file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		entries, err := container.VaultService.ListEntries()
		if err != nil {
			return err
		}

		if len(entries) == 0 {
			ui.PrintWarning("Vault is empty. Nothing to export.")
			return nil
		}

		if exportFile == "" {
			exportFile = fmt.Sprintf("securevault_export.%s", strings.ToLower(exportFormat))
		}

		ui.PrintWarning("CAUTION: Exporting plaintext entries to file %s!", exportFile)
		if !ui.PromptConfirm("Do you wish to continue?") {
			ui.PrintInfo("Export cancelled.")
			return nil
		}

		switch strings.ToLower(exportFormat) {
		case "json":
			if err := storage.ExportJSON(exportFile, entries); err != nil {
				return err
			}
		case "csv":
			if err := storage.ExportCSV(exportFile, entries); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported format '%s'. Use 'json' or 'csv'", exportFormat)
		}

		ui.PrintSuccess("Exported %d entries to %s", len(entries), exportFile)
		return nil
	},
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import vault entries from JSON or CSV file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		if importFile == "" {
			return fmt.Errorf("--file flag is required for import")
		}

		var imported []*models.VaultEntry
		var err error

		switch strings.ToLower(importFormat) {
		case "json":
			imported, err = storage.ImportJSON(importFile)
		case "csv":
			imported, err = storage.ImportCSV(importFile)
		default:
			return fmt.Errorf("unsupported format '%s'. Use 'json' or 'csv'", importFormat)
		}

		if err != nil {
			return fmt.Errorf("import failed: %w", err)
		}

		count := 0
		for _, entry := range imported {
			if err := container.VaultService.AddEntry(entry); err == nil {
				count++
			}
		}

		ui.PrintSuccess("Successfully imported %d entries from %s", count, importFile)
		return nil
	},
}

func init() {
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "export format: json or csv")
	exportCmd.Flags().StringVarP(&exportFile, "file", "o", "", "output file path")

	importCmd.Flags().StringVarP(&importFormat, "format", "f", "json", "import format: json or csv")
	importCmd.Flags().StringVarP(&importFile, "file", "i", "", "input file path")

	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(importCmd)
}
