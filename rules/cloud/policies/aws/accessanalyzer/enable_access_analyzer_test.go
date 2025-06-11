package accessanalyzer

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/accessanalyzer"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckNoSecretsInUserData(t *testing.T) {
	tests := []struct {
		name     string
		input    accessanalyzer.AccessAnalyzer
		expected bool
	}{
		{
			name:     "No analyzers enabled",
			input:    accessanalyzer.AccessAnalyzer{},
			expected: true,
		},
		{
			name: "Analyzer disabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ARN:      misscanTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", misscanTypes.NewTestMetadata()),
						Name:     misscanTypes.String("test", misscanTypes.NewTestMetadata()),
						Active:   misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Analyzer enabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ARN:      misscanTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", misscanTypes.NewTestMetadata()),
						Name:     misscanTypes.String("test", misscanTypes.NewTestMetadata()),
						Active:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.AccessAnalyzer = test.input
			results := CheckEnableAccessAnalyzer.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessAnalyzer.Rule().LongID() {
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
