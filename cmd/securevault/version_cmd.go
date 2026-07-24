package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"securevault/internal/ui"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display SecureVault version and build info",
	Run: func(cmd *cobra.Command, args []string) {
		ui.PrintBanner()
		fmt.Println(" Version    : 1.0.0")
		fmt.Println(" Go Version : 1.25+")
		fmt.Println(" Security   : Argon2id + AES-256-GCM")
		fmt.Println(" Architecture: Clean Architecture")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
