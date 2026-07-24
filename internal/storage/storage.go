// Package storage provides data import and export operations in CSV and JSON formats.
package storage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"securevault/internal/models"
)

func resolveExportPath(filePath, defaultFileName string) string {
	clean := strings.TrimSpace(filePath)
	if clean == "" {
		return defaultFileName
	}
	fi, err := os.Stat(clean)
	if err == nil && fi.IsDir() {
		return filepath.Join(clean, defaultFileName)
	}
	return clean
}

// ExportJSON writes a slice of VaultEntry to a JSON file.
func ExportJSON(filePath string, entries []*models.VaultEntry) error {
	finalPath := resolveExportPath(filePath, "vault_export.json")
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal entries to JSON: %w", err)
	}

	if err := os.WriteFile(finalPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write JSON export file: %w", err)
	}
	return nil
}

// ExportCSV writes a slice of VaultEntry to a CSV file.
func ExportCSV(filePath string, entries []*models.VaultEntry) error {
	finalPath := resolveExportPath(filePath, "vault_export.csv")
	file, err := os.OpenFile(finalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CSV export file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV Header
	header := []string{"title", "website", "username", "password", "notes", "category", "tags", "favorite"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, entry := range entries {
		tagsStr := strings.Join(entry.Tags, ";")
		favStr := "false"
		if entry.Favorite {
			favStr = "true"
		}

		record := []string{
			entry.Title,
			entry.Website,
			entry.Username,
			entry.Password,
			entry.Notes,
			entry.Category,
			tagsStr,
			favStr,
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed writing CSV record for '%s': %w", entry.Title, err)
		}
	}

	return nil
}

// ImportJSON reads entries from a JSON file.
func ImportJSON(filePath string) ([]*models.VaultEntry, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON import file: %w", err)
	}

	var entries []*models.VaultEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse JSON import file: %w", err)
	}

	now := time.Now().UTC()
	for _, entry := range entries {
		if entry.ID == "" {
			entry.ID = uuid.New().String()
		}
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = now
		}
		entry.UpdatedAt = now
	}

	return entries, nil
}

// ImportCSV reads entries from a CSV file.
func ImportCSV(filePath string) ([]*models.VaultEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV import file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	// Read Header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	colIdx := make(map[string]int)
	for idx, col := range header {
		colIdx[strings.ToLower(strings.TrimSpace(col))] = idx
	}

	var entries []*models.VaultEntry
	now := time.Now().UTC()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV record: %w", err)
		}

		getVal := func(colName string) string {
			if idx, ok := colIdx[colName]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		title := getVal("title")
		if title == "" {
			continue // Skip records without title
		}

		favBool, _ := strconv.ParseBool(getVal("favorite"))

		var tags []string
		tagsRaw := getVal("tags")
		if tagsRaw != "" {
			for _, t := range strings.Split(tagsRaw, ";") {
				if trimmed := strings.TrimSpace(t); trimmed != "" {
					tags = append(tags, trimmed)
				}
			}
		}

		category := getVal("category")
		if category == "" {
			category = "General"
		}

		entry := &models.VaultEntry{
			ID:        uuid.New().String(),
			Title:     title,
			Website:   getVal("website"),
			Username:  getVal("username"),
			Password:  getVal("password"),
			Notes:     getVal("notes"),
			Category:  category,
			Tags:      tags,
			Favorite:  favBool,
			CreatedAt: now,
			UpdatedAt: now,
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
