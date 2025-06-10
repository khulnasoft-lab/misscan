package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/openstack"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Compute
		expected bool
	}{
		{
			name: "Firewall rule missing destination address",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    misscanTypes.NewTestMetadata(),
							Enabled:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Destination: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							Source:      misscanTypes.String("10.10.10.1", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule missing source address",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    misscanTypes.NewTestMetadata(),
							Enabled:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Destination: misscanTypes.String("10.10.10.2", misscanTypes.NewTestMetadata()),
							Source:      misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with public destination and source addresses",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    misscanTypes.NewTestMetadata(),
							Enabled:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Destination: misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
							Source:      misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with private destination and source addresses",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    misscanTypes.NewTestMetadata(),
							Enabled:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Destination: misscanTypes.String("10.10.10.1", misscanTypes.NewTestMetadata()),
							Source:      misscanTypes.String("10.10.10.2", misscanTypes.NewTestMetadata()),
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
			testState.OpenStack.Compute = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
