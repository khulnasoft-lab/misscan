package rdb

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicDbAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    rdb.RDB
		expected bool
	}{
		{
			name: "RDB Instance with public access enabled",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:     misscanTypes.NewTestMetadata(),
						PublicAccess: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDB Instance with public access disabled",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:     misscanTypes.NewTestMetadata(),
						PublicAccess: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			results := CheckNoPublicDbAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicDbAccess.Rule().LongID() {
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
