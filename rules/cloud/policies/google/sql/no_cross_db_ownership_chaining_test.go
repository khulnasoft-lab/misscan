package sql

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCrossDbOwnershipChaining(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance cross database ownership chaining enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						DatabaseVersion: misscanTypes.String("SQLSERVER_2017_STANDARD", misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                 misscanTypes.NewTestMetadata(),
								CrossDBOwnershipChaining: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance cross database ownership chaining disabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						DatabaseVersion: misscanTypes.String("SQLSERVER_2017_STANDARD", misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                 misscanTypes.NewTestMetadata(),
								CrossDBOwnershipChaining: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			testState.Google.SQL = test.input
			results := CheckNoCrossDbOwnershipChaining.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCrossDbOwnershipChaining.Rule().LongID() {
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
