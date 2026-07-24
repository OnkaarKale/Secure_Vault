package main

import (
	"github.com/spf13/cobra"

	"securevault/internal/models"
	"securevault/internal/ui"
)

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search vault entries by title, website, username, category, or tags",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		query := args[0]
		entries, err := container.VaultService.ListEntries()
		if err != nil {
			return err
		}

		filter := models.SearchFilter{Query: query}
		results := container.SearchEngine.Filter(entries, filter)

		ui.PrintInfo("Search results for '%s' (%d matches):", query, len(results))
		ui.RenderEntriesTable(results, showPasswords)
		return nil
	},
}

func init() {
	searchCmd.Flags().BoolVarP(&showPasswords, "show-passwords", "p", false, "display plain-text passwords in results table")
	rootCmd.AddCommand(searchCmd)
}
