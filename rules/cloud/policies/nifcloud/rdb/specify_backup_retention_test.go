package rdb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBackupRetentionSpecified(t *testing.T) {
	tests := []struct {
		name     string
		input    rdb.RDB
		expected bool
	}{
		{
			name: "RDB Instance with 1 retention day (default)",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  misscanTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDB Instance with 5 retention days",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  misscanTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: misscanTypes.Int(5, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.RDB = test.input
			results := CheckBackupRetentionSpecified.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckBackupRetentionSpecified.Rule().LongID() {
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
