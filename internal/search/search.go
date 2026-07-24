// Package search provides filtering and multi-field partial string matching engines for vault entries.
package search

import (
	"strings"

	"securevault/internal/models"
	"securevault/internal/utils"
)

// SearchEngine performs multi-field filtering on a collection of VaultEntry structs.
type SearchEngine struct{}

// NewSearchEngine initializes a new SearchEngine instance.
func NewSearchEngine() *SearchEngine {
	return &SearchEngine{}
}

// Filter applies criteria specified in filter to entries and returns matching subset.
func (s *SearchEngine) Filter(entries []*models.VaultEntry, filter models.SearchFilter) []*models.VaultEntry {
	if len(entries) == 0 {
		return nil
	}

	var results []*models.VaultEntry

	queryLower := strings.ToLower(strings.TrimSpace(filter.Query))
	categoryLower := strings.ToLower(strings.TrimSpace(filter.Category))
	tagLower := strings.ToLower(strings.TrimSpace(filter.Tag))

	for _, entry := range entries {
		if entry == nil {
			continue
		}

		if filter.FavoriteOnly && !entry.Favorite {
			continue
		}

		if categoryLower != "" && strings.ToLower(entry.Category) != categoryLower {
			continue
		}

		if tagLower != "" {
			matchedTag := false
			for _, tag := range entry.Tags {
				if strings.ToLower(tag) == tagLower {
					matchedTag = true
					break
				}
			}
			if !matchedTag {
				continue
			}
		}

		if queryLower != "" {
			titleMatch := strings.Contains(strings.ToLower(entry.Title), queryLower)
			websiteMatch := strings.Contains(strings.ToLower(entry.Website), queryLower)
			usernameMatch := strings.Contains(strings.ToLower(entry.Username), queryLower)
			notesMatch := strings.Contains(strings.ToLower(entry.Notes), queryLower)

			tagMatch := false
			for _, tag := range entry.Tags {
				if strings.Contains(strings.ToLower(tag), queryLower) {
					tagMatch = true
					break
				}
			}

			categoryMatch := strings.Contains(strings.ToLower(entry.Category), queryLower)

			if !titleMatch && !websiteMatch && !usernameMatch && !notesMatch && !tagMatch && !categoryMatch {
				continue
			}
		}

		results = append(results, entry)
	}

	return results
}

// SortEntriesByTitle returns a new slice of entries sorted alphabetically by title.
func (s *SearchEngine) SortEntriesByTitle(entries []*models.VaultEntry) []*models.VaultEntry {
	sorted := make([]*models.VaultEntry, len(entries))
	copy(sorted, entries)

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if strings.ToLower(sorted[i].Title) > strings.ToLower(sorted[j].Title) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted
}

// FilterByCategory helper returns entries matching a specific category.
func (s *SearchEngine) FilterByCategory(entries []*models.VaultEntry, category string) []*models.VaultEntry {
	return s.Filter(entries, models.SearchFilter{Category: category})
}

// FilterByTag helper returns entries containing a given tag.
func (s *SearchEngine) FilterByTag(entries []*models.VaultEntry, tag string) []*models.VaultEntry {
	return s.Filter(entries, models.SearchFilter{Tag: tag})
}

// GetFavorites returns only favorite entries.
func (s *SearchEngine) GetFavorites(entries []*models.VaultEntry) []*models.VaultEntry {
	return s.Filter(entries, models.SearchFilter{FavoriteOnly: true})
}

// ExtractCategories collects unique categories across entries.
func ExtractCategories(entries []*models.VaultEntry) []string {
	var categories []string
	for _, entry := range entries {
		if entry.Category != "" && !utils.ContainsString(categories, entry.Category, true) {
			categories = append(categories, entry.Category)
		}
	}
	return categories
}
