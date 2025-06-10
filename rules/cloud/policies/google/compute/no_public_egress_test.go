package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall egress rule with multiple public destination addresses",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: misscanTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: misscanTypes.NewTestMetadata(),
										IsAllow:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
										Enforced: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
									},
									DestinationRanges: []misscanTypes.StringValue{
										misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
										misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall egress rule with public destination address",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: misscanTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: misscanTypes.NewTestMetadata(),
										IsAllow:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
										Enforced: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
									},
									DestinationRanges: []misscanTypes.StringValue{
										misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
									},
								},
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
			testState.Google.Compute = test.input
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicEgress.Rule().LongID() {
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
