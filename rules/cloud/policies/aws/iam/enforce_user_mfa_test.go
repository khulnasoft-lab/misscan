package iam

import (
	"testing"
	"time"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceUserMFA(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "user logged in without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("other", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.Time(time.Now(), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "user without mfa never logged in",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("other", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "user with mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("root", misscanTypes.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								IsVirtual: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.IAM = test.input
			results := CheckEnforceUserMFA.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceUserMFA.Rule().LongID() {
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
