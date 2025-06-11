package elb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckHttpNotUsed(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer listener with HTTP protocol",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String(elb.TypeApplication, misscanTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("forward", misscanTypes.NewTestMetadata()),
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
			name: "Load balancer listener with HTTP protocol but redirect default action",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String(elb.TypeApplication, misscanTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("redirect", misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol but redirect among multiple default actions",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String(elb.TypeApplication, misscanTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("forward", misscanTypes.NewTestMetadata()),
									},
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("redirect", misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String(elb.TypeApplication, misscanTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("forward", misscanTypes.NewTestMetadata()),
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
			testState.AWS.ELB = test.input
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
