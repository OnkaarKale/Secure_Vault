package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"securevault/internal/ui"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit vault security health and perform payload integrity checks",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureUnlocked(); err != nil {
			return err
		}

		ui.ShowSpinner("Running vault security analysis and integrity verification...", 700)

		if err := container.VaultService.VerifyIntegrity(); err != nil {
			ui.PrintError("Integrity verification failed: %v", err)
			return err
		}
		ui.PrintSuccess("Database integrity check passed (0 tampered entries).")

		report, err := container.VaultService.AuditSecurity()
		if err != nil {
			return err
		}

		fmt.Println(ui.Bold("\n================ Security Audit Report ================"))
		fmt.Printf(" Total Vault Entries : %d\n", report.TotalEntries)
		fmt.Printf(" Health Score        : %s / 100\n", ui.Green(fmt.Sprintf("%d", report.Score)))
		fmt.Printf(" Weak Passwords      : %d\n", len(report.WeakPasswords))
		fmt.Printf(" Duplicate Passwords : %d\n", len(report.DuplicatePasswords))
		fmt.Printf(" Old Passwords (>90d): %d\n", len(report.OldPasswords))

		if len(report.WeakPasswords) > 0 {
			fmt.Println(ui.Yellow("\n [!] Weak Passwords Detected:"))
			for _, entry := range report.WeakPasswords {
				fmt.Printf("   • %s (%s)\n", entry.Title, entry.ID)
			}
		}

		if len(report.DuplicatePasswords) > 0 {
			fmt.Println(ui.Red("\n [!] Duplicate Passwords Detected:"))
			for pass, titles := range report.DuplicatePasswords {
				_ = pass
				fmt.Printf("   • Shared across: %v\n", titles)
			}
		}

		fmt.Println(ui.Bold("=======================================================\n"))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
