package mq

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/mq"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableGeneralLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    mq.MQ
		expected bool
	}{
		{
			name: "AWS MQ Broker without general logging",
			input: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							General:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS MQ Broker with general logging",
			input: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							General:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.MQ = test.input
			results := CheckEnableGeneralLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableGeneralLogging.Rule().LongID() {
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
