package nas

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToNASSecurityGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    nas.NAS
		expected bool
	}{
		{
			name: "NIFCLOUD nas security group with no description provided",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with default description",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("Managed by Terraform", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with proper description",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("some proper description", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.NAS = test.input
			results := CheckAddDescriptionToNASSecurityGroup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddDescriptionToNASSecurityGroup.Rule().LongID() {
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
