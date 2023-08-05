package main

import (
	"fmt"
	"testing"
)

func Test_profanityFilter(t *testing.T) {
	tests := []struct {
		given    string
		expected string
	}{
		{"I hear Mastodon is better than Chirpy. sharbert I need to migrate", "I hear Mastodon is better than Chirpy. **** I need to migrate"},
		{"How about you Sharbert yourself, you foRnax of a kerfuffle", "How about you **** yourself, you **** of a ****"},
	}

	for _, example := range tests {
		testName := fmt.Sprintf("Given %s,\nWhen I filter the string,\nI should get %s", example.given, example.expected)
		t.Run(testName, func(t *testing.T) {
			actual := ProfanityFilter(example.given)
			if actual != example.expected {
				t.Errorf("Expected %s, but got %s", example.expected, actual)
			}
		})
	}
}
