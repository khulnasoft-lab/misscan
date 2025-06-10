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

func TestCheckUnusedCredentialsDisabled45Days(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "User logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("user", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.Time(time.Now(), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("user", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("AKIACKCEVSQ6C2EXAMPLE", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CreationDate: misscanTypes.Time(time.Now().Add(-time.Hour*24*30), misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.Time(time.Now(), misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "User logged in 50 days ago",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("user", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.Time(time.Now().Add(-time.Hour*24*50), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "User last used access key 50 days ago but it is no longer active",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("user", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("AKIACKCEVSQ6C2EXAMPLE", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								CreationDate: misscanTypes.Time(time.Now().Add(-time.Hour*24*120), misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.Time(time.Now().Add(-time.Hour*24*50), misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "User last used access key 50 days ago and it is active",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("user", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("AKIACKCEVSQ6C2EXAMPLE", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CreationDate: misscanTypes.Time(time.Now().Add(-time.Hour*24*120), misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.Time(time.Now().Add(-time.Hour*24*50), misscanTypes.NewTestMetadata()),
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
			results := CheckUnusedCredentialsDisabled45Days.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUnusedCredentialsDisabled45Days.Rule().LongID() {
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
