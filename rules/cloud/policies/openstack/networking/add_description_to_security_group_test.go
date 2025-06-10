package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/openstack"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecurityGroupHasDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Networking
		expected bool
	}{
		{
			name: "Security group missing description",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group with description",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("this is for connecting to the database", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Networking = test.input
			results := CheckSecurityGroupHasDescription.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecurityGroupHasDescription.Rule().LongID() {
					found = true
				}
			}
			assert.Equal(t, test.expected, found, "Rule should have been found")
		})
	}
}
