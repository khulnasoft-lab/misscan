package elb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer listener using TLS v1.0",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								TLSPolicy: misscanTypes.String("ELBSecurityPolicy-TLS-1-0-2015-04", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								TLSPolicy: misscanTypes.String("ELBSecurityPolicy-TLS-1-2-2017-01", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener using TLS v1.3",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								TLSPolicy: misscanTypes.String("ELBSecurityPolicy-TLS13-1-2-2021-06", misscanTypes.NewTestMetadata()),
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
