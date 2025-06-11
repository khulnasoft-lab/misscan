package bigquery

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/bigquery"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    bigquery.BigQuery
		expected bool
	}{
		{
			name: "positive result",
			input: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: misscanTypes.String(
									bigquery.SpecialGroupAllAuthenticatedUsers,
									misscanTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: misscanTypes.String(
									"anotherGroup",
									misscanTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.BigQuery = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
