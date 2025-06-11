package sam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableHttpApiAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "HTTP API logging not configured",
			input: sam.SAM{
				HttpAPIs: []sam.HttpAPI{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              misscanTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "HTTP API logging configured",
			input: sam.SAM{
				HttpAPIs: []sam.HttpAPI{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              misscanTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: misscanTypes.String("log-group-arn", misscanTypes.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckEnableHttpApiAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableHttpApiAccessLogging.Rule().LongID() {
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
