package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"securevault/internal/generator"
	"securevault/internal/models"
	"securevault/internal/ui"
)

var (
	genLength       int
	genSymbols      bool
	genNumbers      bool
	genUpper        bool
	genLower        bool
	genNoAmbiguous  bool
	genPassphrase   bool
	genUsername     bool
	evaluatePass    string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate random passwords, passphrases, usernames, or analyze password strength",
	RunE: func(cmd *cobra.Command, args []string) error {
		if evaluatePass != "" {
			strength := generator.EvaluateStrength(evaluatePass)
			fmt.Println(ui.Bold("\n--- Password Strength Analysis ---"))
			fmt.Printf(" Rating  : %s\n", ui.Magenta(strength.Rating))
			fmt.Printf(" Score   : %d / 4\n", strength.Score)
			fmt.Printf(" Entropy : %.2f bits\n", strength.Entropy)
			if len(strength.Feedback) > 0 {
				fmt.Println(ui.Yellow(" Feedback:"))
				for _, fb := range strength.Feedback {
					fmt.Printf("  • %s\n", fb)
				}
			}
			fmt.Println(ui.Bold("----------------------------------\n"))
			return nil
		}

		if genUsername {
			user, err := generator.GenerateUsername()
			if err != nil {
				return err
			}
			ui.PrintSuccess("Generated Username: %s", ui.Green(user))
			return nil
		}

		if genPassphrase {
			opts := models.DefaultPassphraseOptions()
			phrase, err := generator.GeneratePassphrase(opts)
			if err != nil {
				return err
			}
			ui.PrintSuccess("Generated Passphrase: %s", ui.Green(phrase))
			return nil
		}

		opts := models.GeneratorOptions{
			Length:           genLength,
			IncludeUppercase: genUpper,
			IncludeLowercase: genLower,
			IncludeNumbers:   genNumbers,
			IncludeSymbols:   genSymbols,
			ExcludeAmbiguous: genNoAmbiguous,
		}

		pass, err := generator.GeneratePassword(opts)
		if err != nil {
			return err
		}

		strength := generator.EvaluateStrength(pass)
		ui.PrintSuccess("Generated Password: %s (Entropy: %.1f bits, Rating: %s)", ui.Green(pass), strength.Entropy, strength.Rating)
		return nil
	},
}

func init() {
	generateCmd.Flags().IntVarP(&genLength, "length", "l", 20, "length of generated password")
	generateCmd.Flags().BoolVarP(&genSymbols, "symbols", "s", true, "include special symbols")
	generateCmd.Flags().BoolVarP(&genNumbers, "numbers", "n", true, "include numeric digits")
	generateCmd.Flags().BoolVarP(&genUpper, "uppercase", "u", true, "include uppercase letters")
	generateCmd.Flags().BoolVarP(&genLower, "lowercase", "w", true, "include lowercase letters")
	generateCmd.Flags().BoolVar(&genNoAmbiguous, "no-ambiguous", true, "exclude ambiguous characters (1, l, O, 0, etc.)")
	generateCmd.Flags().BoolVar(&genPassphrase, "passphrase", false, "generate a word-based passphrase")
	generateCmd.Flags().BoolVar(&genUsername, "username", false, "generate a random username")
	generateCmd.Flags().StringVarP(&evaluatePass, "evaluate", "e", "", "evaluate strength of a given password")

	rootCmd.AddCommand(generateCmd)
}
