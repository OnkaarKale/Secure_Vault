package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"securevault/internal/ui"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Display active runtime configuration parameters",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := container.Config
		fmt.Println(ui.Bold("\n--- Active Configuration ---"))
		fmt.Printf(" Database Path           : %s\n", cfg.DatabasePath)
		fmt.Printf(" Backup Directory        : %s\n", cfg.BackupDir)
		fmt.Printf(" Log Level               : %s\n", cfg.LogLevel)
		fmt.Printf(" Log File                : %s\n", cfg.LogFile)
		fmt.Printf(" Session Timeout (min)   : %d\n", cfg.SessionTimeoutMinutes)
		fmt.Printf(" Clipboard Timeout (sec) : %d\n", cfg.ClipboardTimeoutSec)
		fmt.Printf(" Max Login Attempts      : %d\n", cfg.MaxLoginAttempts)
		fmt.Printf(" Lockout Duration (min)  : %d\n", cfg.LockoutDurationMinutes)
		fmt.Printf(" Backup Rotation Count   : %d\n", cfg.BackupRotationCount)
		fmt.Println(ui.Bold("----------------------------\n"))
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
