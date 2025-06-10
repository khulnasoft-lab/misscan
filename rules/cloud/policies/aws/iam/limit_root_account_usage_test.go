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

func TestCheckLimitRootAccountUsage(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user, never logged in",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("root", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user, logged in months ago",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("other", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.Time(time.Now().Add(-time.Hour*24*90), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user, logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("root", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.Time(time.Now().Add(-time.Hour), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "other user, logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("other", misscanTypes.NewTestMetadata()),
						LastAccess: misscanTypes.Time(time.Now().Add(-time.Hour), misscanTypes.NewTestMetadata()),
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
			results := checkLimitRootAccountUsage.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkLimitRootAccountUsage.Rule().LongID() {
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
