package network

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/network"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group outbound rule with wildcard destination address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Outbound: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								DestinationAddresses: []misscanTypes.StringValue{
									misscanTypes.String("*", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group outbound rule with private destination address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Outbound: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								DestinationAddresses: []misscanTypes.StringValue{
									misscanTypes.String("10.0.0.0/16", misscanTypes.NewTestMetadata()),
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
			testState.Azure.Network = test.input
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
