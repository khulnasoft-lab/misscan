package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoUserAttachedPolicies(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "user without policies attached",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "user with a policy attached",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Name:     misscanTypes.String("another.policy", misscanTypes.NewTestMetadata()),
								Document: iam.Document{
									Metadata: misscanTypes.NewTestMetadata(),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := checkNoUserAttachedPolicies.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkNoUserAttachedPolicies.Rule().LongID() {
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
