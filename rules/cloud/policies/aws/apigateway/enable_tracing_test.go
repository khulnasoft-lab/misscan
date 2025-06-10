package apigateway

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	v1 "github.com/khulnasoft-lab/misscan/pkg/providers/aws/apigateway/v1"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableTracing(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API Gateway stage with X-Ray tracing disabled",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata:           misscanTypes.NewTestMetadata(),
								XRayTracingEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway stage with X-Ray tracing enabled",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata:           misscanTypes.NewTestMetadata(),
								XRayTracingEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			results := CheckEnableTracing.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableTracing.Rule().LongID() {
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
