package monitor

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/monitor"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckCaptureAllActivities(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log profile captures only write activities",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Categories: []misscanTypes.StringValue{
							misscanTypes.String("Write", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures action, write, delete activities",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Categories: []misscanTypes.StringValue{
							misscanTypes.String("Action", misscanTypes.NewTestMetadata()),
							misscanTypes.String("Write", misscanTypes.NewTestMetadata()),
							misscanTypes.String("Delete", misscanTypes.NewTestMetadata()),
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
			results := CheckCaptureAllActivities.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckCaptureAllActivities.Rule().LongID() {
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
