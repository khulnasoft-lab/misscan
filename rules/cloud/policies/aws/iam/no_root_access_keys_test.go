package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoRootAccessKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user without access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("root", misscanTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "other user without access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("other", misscanTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "other user with access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("other", misscanTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("BLAH", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CreationDate: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with inactive access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("root", misscanTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("BLAH", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								CreationDate: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with active access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("root", misscanTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("BLAH", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CreationDate: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
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
			results := checkNoRootAccessKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkNoRootAccessKeys.Rule().LongID() {
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
