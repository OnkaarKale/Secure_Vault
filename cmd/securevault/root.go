// Package main is the entrypoint for the securevault CLI executable.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"securevault/internal/service"
	"securevault/internal/ui"
)

var (
	cfgFile   string
	verbose   bool
	container *service.Container
)

var rootCmd = &cobra.Command{
	Use:   "securevault",
	Short: "SecureVault is a production-quality command line password manager.",
	Long: `SecureVault is an encrypted CLI password manager built with Go.
It enforces Argon2id key derivation, AES-256-GCM authenticated encryption, zero plaintext storage,
auto-clearing clipboards, encrypted backups, and security auditing.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		container, err = service.NewContainer(cfgFile)
		if err != nil {
			return fmt.Errorf("initialization error: %w", err)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if container != nil {
			container.Close()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunInteractiveMenu()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		ui.PrintError("%v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default is ./configs/config.yaml or ~/.securevault/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}
