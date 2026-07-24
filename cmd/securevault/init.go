package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"securevault/internal/ui"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new user account and encrypted vault",
	Long:  `Initialize the vault database and configure your email/gmail username and master password.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.PrintBanner()

		ui.PrintInfo("Welcome to SecureVault! Let's set up your user account and master password.")
		ui.PrintWarning("IMPORTANT: If you lose your master password, your vault cannot be recovered!")

		email, err := ui.PromptInput("Enter Email / Gmail Username: ")
		if err != nil {
			return err
		}
		if email == "" {
			email = "admin@securevault.local"
		}

		pass1, err := ui.PromptPassword("Enter new Master Password: ")
		if err != nil {
			return err
		}
		if len(pass1) < 8 {
			return fmt.Errorf("master password must be at least 8 characters long")
		}

		pass2, err := ui.PromptPassword("Confirm Master Password: ")
		if err != nil {
			return err
		}

		if pass1 != pass2 {
			return fmt.Errorf("passwords do not match")
		}

		ui.ShowSpinner("Initializing encrypted vault with Argon2id parameters...", 800)

		_, err = container.AuthService.SignUp(email, pass1)
		if err != nil {
			return err
		}

		ui.PrintSuccess("Vault initialized successfully for '%s'! Active session unlocked.", email)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
