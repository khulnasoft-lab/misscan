package network

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Load balancer listener using TLS v1.0",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								TLSPolicy: misscanTypes.String("Standard Ciphers A ver1", misscanTypes.NewTestMetadata()),
								Protocol:  misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								TLSPolicy: misscanTypes.String("Standard Ciphers D ver1", misscanTypes.NewTestMetadata()),
								Protocol:  misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener using ICMP",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								TLSPolicy: misscanTypes.String("", misscanTypes.NewTestMetadata()),
								Protocol:  misscanTypes.String("ICMP", misscanTypes.NewTestMetadata()),
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
			testState.Nifcloud.Network = test.input
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
