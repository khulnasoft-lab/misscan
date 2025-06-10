package sql

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableBackup(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Database instance backups disabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						IsReplica: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Database instance backups enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						IsReplica: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Read replica does not require backups",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						IsReplica: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			results := CheckEnableBackup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableBackup.Rule().LongID() {
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
