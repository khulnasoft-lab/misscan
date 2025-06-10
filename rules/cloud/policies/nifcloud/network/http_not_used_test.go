package network

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckHttpNotUsed(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Elastic Load balancer listener with HTTP protocol on global",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     misscanTypes.NewTestMetadata(),
							NetworkID:    misscanTypes.String("net-COMMON_GLOBAL", misscanTypes.NewTestMetadata()),
							IsVipNetwork: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elastic Load balancer listener with HTTP protocol on internal",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     misscanTypes.NewTestMetadata(),
							NetworkID:    misscanTypes.String("some-network", misscanTypes.NewTestMetadata()),
							IsVipNetwork: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Elastic Load balancer listener with HTTPS protocol on global",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     misscanTypes.NewTestMetadata(),
							NetworkID:    misscanTypes.String("net-COMMON_GLOBAL", misscanTypes.NewTestMetadata()),
							IsVipNetwork: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
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
			results := CheckHttpNotUsed.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckHttpNotUsed.Rule().LongID() {
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
