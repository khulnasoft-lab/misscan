package actions

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/github"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlainTextActionEnvironmentSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    []github.EnvironmentSecret
		expected bool
	}{
		{
			name: "Github actions environment secret has plain text value",
			input: []github.EnvironmentSecret{
				{
					Metadata:       misscanTypes.NewTestMetadata(),
					PlainTextValue: misscanTypes.String("sensitive secret string", misscanTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Github actions environment secret has no plain text value",
			input: []github.EnvironmentSecret{
				{
					Metadata:       misscanTypes.NewTestMetadata(),
					PlainTextValue: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.GitHub.EnvironmentSecrets = test.input
			results := CheckNoPlainTextActionEnvironmentSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPlainTextActionEnvironmentSecrets.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
