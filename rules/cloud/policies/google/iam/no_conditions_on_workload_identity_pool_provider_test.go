package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoConditionOnWorkloadIdentityPoolProvider(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Workload identity pool without condition",
			input: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       misscanTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         misscanTypes.String("example-pool", misscanTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: misscanTypes.String("example-provider", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Workload identity pool with empty condition",
			input: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       misscanTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         misscanTypes.String("example-pool", misscanTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: misscanTypes.String("example-provider", misscanTypes.NewTestMetadata()),
						AttributeCondition:             misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Workload identity pool with non-empty condition",
			input: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       misscanTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         misscanTypes.String("example-pool", misscanTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: misscanTypes.String("example-provider", misscanTypes.NewTestMetadata()),
						AttributeCondition:             misscanTypes.String("assertion.repository_owner=='your-github-organization'", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.IAM = test.input
			results := CheckNoConditionOnWorkloadIdentityPoolProvider.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoConditionOnWorkloadIdentityPoolProvider.Rule().LongID() {
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
