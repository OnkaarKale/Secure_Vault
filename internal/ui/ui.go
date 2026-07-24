// Package ui provides terminal styling, ASCII banners, color utilities, table formatting, and prompts.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"

	"securevault/internal/models"
	"securevault/internal/utils"
)

var (
	Cyan    = color.New(color.FgCyan, color.Bold).SprintfFunc()
	Green   = color.New(color.FgGreen, color.Bold).SprintfFunc()
	Yellow  = color.New(color.FgYellow, color.Bold).SprintfFunc()
	Red     = color.New(color.FgRed, color.Bold).SprintfFunc()
	Magenta = color.New(color.FgMagenta, color.Bold).SprintfFunc()
	White   = color.New(color.FgWhite).SprintfFunc()
	Bold    = color.New(color.Bold).SprintfFunc()
)

// PrintBanner renders a sleek, modern terminal header.
func PrintBanner() {
	banner := `
┌───────────────────────────────────────────────────────────────────────────┐
│                      🔐  S E C U R E   V A U L T                          │
│             Production-Quality Offline AES-256-GCM Password Manager        │
└───────────────────────────────────────────────────────────────────────────┘`
	fmt.Println(Cyan(banner))
}

// PrintSuccess prints a formatted success message.
func PrintSuccess(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", Green("✔"), formatted)
}

// PrintError prints a formatted error message.
func PrintError(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", Red("✖"), formatted)
}

// PrintWarning prints a formatted warning message.
func PrintWarning(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", Yellow("⚠"), formatted)
}

// PrintInfo prints an informational message.
func PrintInfo(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", Cyan("ℹ"), formatted)
}

// RenderEntriesTable formats a list of VaultEntry structs into a clean terminal table.
func RenderEntriesTable(entries []*models.VaultEntry, showPasswords bool) {
	if len(entries) == 0 {
		PrintWarning("No vault entries found.")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Title", "Category", "Username", "Password", "Fav", "Updated"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
	)

	for _, entry := range entries {
		shortID := entry.ID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		favStr := ""
		if entry.Favorite {
			favStr = Yellow("★")
		}

		passStr := "••••••••"
		if showPasswords {
			passStr = entry.Password
		}

		table.Append([]string{
			shortID,
			entry.Title,
			entry.Category,
			entry.Username,
			passStr,
			favStr,
			utils.FormatTime(entry.UpdatedAt),
		})
	}

	table.Render()
}

// RenderEntryDetails displays a full card view of a single VaultEntry.
func RenderEntryDetails(entry *models.VaultEntry, showPassword bool) {
	favStr := "No"
	if entry.Favorite {
		favStr = Yellow("Yes ★")
	}

	passStr := "••••••••"
	if showPassword {
		passStr = entry.Password
	}

	fmt.Println(Bold("\n------------------- Entry Details -------------------"))
	fmt.Printf(" %-12s: %s\n", Bold("ID"), entry.ID)
	fmt.Printf(" %-12s: %s\n", Bold("Title"), Green(entry.Title))
	fmt.Printf(" %-12s: %s\n", Bold("Category"), entry.Category)
	fmt.Printf(" %-12s: %s\n", Bold("Website"), entry.Website)
	fmt.Printf(" %-12s: %s\n", Bold("Username"), entry.Username)
	fmt.Printf(" %-12s: %s\n", Bold("Password"), Magenta(passStr))
	fmt.Printf(" %-12s: %s\n", Bold("Tags"), strings.Join(entry.Tags, ", "))
	fmt.Printf(" %-12s: %s\n", Bold("Favorite"), favStr)
	fmt.Printf(" %-12s: %s\n", Bold("Created"), utils.FormatTime(entry.CreatedAt))
	fmt.Printf(" %-12s: %s\n", Bold("Updated"), utils.FormatTime(entry.UpdatedAt))
	if entry.Notes != "" {
		fmt.Printf(" %-12s: %s\n", Bold("Notes"), entry.Notes)
	}
	fmt.Println(Bold("----------------------------------------------------\n"))
}

var stdinReader = bufio.NewReader(os.Stdin)

// PromptPassword securely prompts the user for a password without echoing input.
func PromptPassword(prompt string) (string, error) {
	fmt.Print(Bold(prompt))
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := stdinReader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

// PromptInput prompts the user for a required string input.
func PromptInput(prompt string) (string, error) {
	fmt.Print(Bold(prompt))
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", fmt.Errorf("input cannot be empty")
	}
	return trimmed, nil
}

// PromptString reads a single line of string input from standard input.
func PromptString(prompt string, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", Bold(prompt), defaultValue)
	} else {
		fmt.Printf("%s: ", Bold(prompt))
	}

	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return defaultValue
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return defaultValue
	}
	return trimmed
}

// PromptConfirm asks for a yes/no confirmation.
func PromptConfirm(prompt string) bool {
	res := PromptString(fmt.Sprintf("%s (y/N)", prompt), "n")
	return strings.ToLower(res) == "y" || strings.ToLower(res) == "yes"
}

// ShowSpinner displays a brief loading animation.
func ShowSpinner(message string, duration time.Duration) {
	spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	endTime := time.Now().Add(duration)
	i := 0
	for time.Now().Before(endTime) {
		fmt.Printf("\r%s %s", Cyan(spinChars[i%len(spinChars)]), message)
		time.Sleep(80 * time.Millisecond)
		i++
	}
	fmt.Printf("\r%s %s\n", Green("✔"), message)
}
