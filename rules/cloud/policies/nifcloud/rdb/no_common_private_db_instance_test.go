package rdb

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateDBInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    rdb.RDB
		expected bool
	}{
		{
			name: "NIFCLOUD db instance with common private",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						NetworkID: misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD db instance with private LAN",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						NetworkID: misscanTypes.String("net-some-private-lan", misscanTypes.NewTestMetadata()),
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
			results := CheckNoCommonPrivateDBInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateDBInstance.Rule().LongID() {
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
