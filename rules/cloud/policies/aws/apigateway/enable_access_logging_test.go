package apigateway

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	v1 "github.com/khulnasoft-lab/misscan/pkg/providers/aws/apigateway/v1"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API Gateway stage with no log group ARN",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              misscanTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: misscanTypes.String("", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway stage with log group ARN",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              misscanTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: misscanTypes.String("log-group-arn", misscanTypes.NewTestMetadata()),
								},
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
			testState.AWS.APIGateway.V1 = test.input
			results := CheckEnableAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessLogging.Rule().LongID() {
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
