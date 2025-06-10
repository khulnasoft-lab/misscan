package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRootMFAEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("root", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "other user without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("other", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with mfa",
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
			results := checkRootMFAEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkRootMFAEnabled.Rule().LongID() {
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
