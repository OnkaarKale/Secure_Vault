package search

import (
	"testing"

	"securevault/internal/models"
)

func TestSearchEngineFilter(t *testing.T) {
	engine := NewSearchEngine()

	entries := []*models.VaultEntry{
		{ID: "1", Title: "GitHub", Website: "github.com", Username: "octocat", Category: "Work", Favorite: true},
		{ID: "2", Title: "Google", Website: "google.com", Username: "user@gmail.com", Category: "Personal", Favorite: false},
		{ID: "3", Title: "AWS Console", Website: "aws.amazon.com", Username: "admin", Category: "Work", Favorite: true},
	}

	filter := models.SearchFilter{Query: "git"}
	results := engine.Filter(entries, filter)
	if len(results) != 1 || results[0].Title != "GitHub" {
		t.Errorf("expected 1 result for query 'git', got %d", len(results))
	}

	favFilter := models.SearchFilter{FavoriteOnly: true}
	favResults := engine.Filter(entries, favFilter)
	if len(favResults) != 2 {
		t.Errorf("expected 2 favorite entries, got %d", len(favResults))
	}

	catFilter := models.SearchFilter{Category: "Work"}
	catResults := engine.Filter(entries, catFilter)
	if len(catResults) != 2 {
		t.Errorf("expected 2 work entries, got %d", len(catResults))
	}
}
