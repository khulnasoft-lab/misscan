package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireLowercaseInPasswords(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM password policy lowercase not required",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         misscanTypes.NewTestMetadata(),
					RequireLowercase: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "IAM password policy lowercase required",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         misscanTypes.NewTestMetadata(),
					RequireLowercase: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRequireLowercaseInPasswords.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireLowercaseInPasswords.Rule().LongID() {
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
