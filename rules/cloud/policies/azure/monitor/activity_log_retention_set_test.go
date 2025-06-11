package monitor

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/monitor"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckActivityLogRetentionSet(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log retention policy disabled",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(365, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 90 days",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(90, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 365 days",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(365, misscanTypes.NewTestMetadata()),
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
			testState.Azure.Monitor = test.input
			results := CheckActivityLogRetentionSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckActivityLogRetentionSet.Rule().LongID() {
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
