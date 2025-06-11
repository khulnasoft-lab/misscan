package network

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/network"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRetentionPolicySet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Network watcher flow log retention policy disabled",
			input: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(100, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 30 days",
			input: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(30, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 100 days",
			input: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(100, misscanTypes.NewTestMetadata()),
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
			testState.Azure.Network = test.input
			results := CheckRetentionPolicySet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRetentionPolicySet.Rule().LongID() {
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
