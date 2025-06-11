package apigateway

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	v1 "github.com/khulnasoft-lab/misscan/pkg/providers/aws/apigateway/v1"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API GET method without authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          misscanTypes.NewTestMetadata(),
										HTTPMethod:        misscanTypes.String("GET", misscanTypes.NewTestMetadata()),
										APIKeyRequired:    misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										AuthorizationType: misscanTypes.String(v1.AuthorizationNone, misscanTypes.NewTestMetadata()),
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
			name: "API OPTION method without authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          misscanTypes.NewTestMetadata(),
										HTTPMethod:        misscanTypes.String("OPTION", misscanTypes.NewTestMetadata()),
										APIKeyRequired:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
										AuthorizationType: misscanTypes.String(v1.AuthorizationNone, misscanTypes.NewTestMetadata()),
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
			name: "API GET method with IAM authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          misscanTypes.NewTestMetadata(),
										HTTPMethod:        misscanTypes.String("GET", misscanTypes.NewTestMetadata()),
										APIKeyRequired:    misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										AuthorizationType: misscanTypes.String(v1.AuthorizationIAM, misscanTypes.NewTestMetadata()),
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
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
