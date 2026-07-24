package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"securevault/internal/ui"
)

var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Create a new user account with Email/Gmail and Master Password",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, err := ui.PromptInput("Enter Email / Gmail Username: ")
		if err != nil {
			return err
		}
		pass1, err := ui.PromptPassword("Enter Master Password: ")
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
		ui.ShowSpinner("Deriving Argon2id key and initializing user vault...", 500)
		_, err = container.AuthService.SignUp(email, pass1)
		if err != nil {
			return err
		}
		ui.PrintSuccess("User account registered successfully for '%s'! Active session unlocked.", email)
		return nil
	},
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Unlock the vault session using your Email/Gmail and master password",
	RunE: func(cmd *cobra.Command, args []string) error {
		init, err := container.AuthService.IsInitialized()
		if err != nil {
			return err
		}
		if !init {
			return fmt.Errorf("vault is not initialized yet. Run 'securevault init' or 'securevault signup' first")
		}

		if container.SessionManager.IsUnlocked() {
			ui.PrintInfo("Vault session is already unlocked.")
			return nil
		}

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
			return err
		}

		ui.PrintSuccess("Authentication successful! Vault unlocked for '%s'.", email)
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Lock active vault session and wipe encryption keys from memory",
	Run: func(cmd *cobra.Command, args []string) {
		container.AuthService.Logout()
		ui.PrintSuccess("Vault locked. Active session cleared.")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check vault lock status, registered users, and database statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		init, err := container.AuthService.IsInitialized()
		if err != nil {
			return err
		}

		fmt.Println(ui.Bold("\n--- Vault Status ---"))
		if !init {
			ui.PrintWarning("Status: Uninitialized (0 registered users)")
			return nil
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
		fmt.Println(ui.Bold("--------------------\n"))
		return nil
	},
}

var changePassCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change vault master password and re-encrypt all vault entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		init, err := container.AuthService.IsInitialized()
		if err != nil || !init {
			return fmt.Errorf("vault is not initialized")
		}

		currPass, err := ui.PromptPassword("Enter Current Master Password: ")
		if err != nil {
			return err
		}

		newPass1, err := ui.PromptPassword("Enter New Master Password: ")
		if err != nil {
			return err
		}
		if len(newPass1) < 8 {
			return fmt.Errorf("new password must be at least 8 characters long")
		}

		newPass2, err := ui.PromptPassword("Confirm New Master Password: ")
		if err != nil {
			return err
		}

		if newPass1 != newPass2 {
			return fmt.Errorf("passwords do not match")
		}

		ui.ShowSpinner("Re-encrypting all entries with new master key...", 1000)

		if err := container.AuthService.ChangeMasterPassword(currPass, newPass1); err != nil {
			return err
		}

		ui.PrintSuccess("Master password changed and all vault entries successfully re-encrypted!")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signupCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(changePassCmd)
}
