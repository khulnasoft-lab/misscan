package network

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/network"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDisableRdpFromInternet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group inbound rule allowing RDP access from the Internet",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Outbound: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								SourceAddresses: []misscanTypes.StringValue{
									misscanTypes.String("*", misscanTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								Protocol: misscanTypes.String("Tcp", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group inbound rule allowing RDP access from a specific address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Outbound: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								SourceAddresses: []misscanTypes.StringValue{
									misscanTypes.String("4.53.160.75", misscanTypes.NewTestMetadata()),
								},
								Protocol: misscanTypes.String("Tcp", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group inbound rule allowing only ICMP",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Outbound: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								SourceAddresses: []misscanTypes.StringValue{
									misscanTypes.String("*", misscanTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								Protocol: misscanTypes.String("Icmp", misscanTypes.NewTestMetadata()),
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
			testState.Azure.Network = test.input
			results := CheckDisableRdpFromInternet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDisableRdpFromInternet.Rule().LongID() {
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
