package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPasswordReuse(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM with 1 password that can't be reused (min)",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             misscanTypes.NewTestMetadata(),
					ReusePreventionCount: misscanTypes.Int(1, misscanTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "IAM with 5 passwords that can't be reused",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             misscanTypes.NewTestMetadata(),
					ReusePreventionCount: misscanTypes.Int(5, misscanTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckNoPasswordReuse.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPasswordReuse.Rule().LongID() {
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
