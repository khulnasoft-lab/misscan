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

func TestCheckLimitUserAccessKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Single active access key",
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
			name: "One active, one inactive access key",
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
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("AKIACKCEVSQ6C2EXAMPLE", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			name: "Two inactive keys",
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
								CreationDate: misscanTypes.Time(time.Now().Add(-time.Hour*24*30), misscanTypes.NewTestMetadata()),
								LastAccess:   misscanTypes.Time(time.Now(), misscanTypes.NewTestMetadata()),
							},
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								AccessKeyId:  misscanTypes.String("AKIACKCEVSQ6C2EXAMPLE", misscanTypes.NewTestMetadata()),
								Active:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			name: "Two active keys",
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
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckLimitUserAccessKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitUserAccessKeys.Rule().LongID() {
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
