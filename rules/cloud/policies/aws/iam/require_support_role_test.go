package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireSupportRole(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name:     "No support role",
			input:    iam.IAM{},
			expected: true,
		},
		{
			name: "Has support role",
			input: iam.IAM{
				Roles: []iam.Role{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Builtin:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Name:     misscanTypes.String("AWSSupportRole", misscanTypes.NewTestMetadata()),
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
			results := CheckRequireSupportRole.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireSupportRole.Rule().LongID() {
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
