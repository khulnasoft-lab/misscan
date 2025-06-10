package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean/compute"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall inbound rule with multiple public source addresses",
			input: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								SourceAddresses: []misscanTypes.StringValue{
									misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
									misscanTypes.String("::/0", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall inbound rule with a private source address",
			input: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								SourceAddresses: []misscanTypes.StringValue{
									misscanTypes.String("192.168.1.0/24", misscanTypes.NewTestMetadata()),
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
			testState.DigitalOcean.Compute = test.input
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.Rule().LongID() {
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
