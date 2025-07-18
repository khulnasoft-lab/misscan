package apigateway

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	v1 "github.com/khulnasoft-lab/misscan/pkg/providers/aws/apigateway/v1"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableCacheEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API Gateway stage with unencrypted cache",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           misscanTypes.NewTestMetadata(),
										CacheDataEncrypted: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										CacheEnabled:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway stage with encrypted cache",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           misscanTypes.NewTestMetadata(),
										CacheDataEncrypted: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
										CacheEnabled:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API Gateway stage with caching disabled",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           misscanTypes.NewTestMetadata(),
										CacheDataEncrypted: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										CacheEnabled:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
									},
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
			results := CheckEnableCacheEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableCacheEncryption.Rule().LongID() {
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
