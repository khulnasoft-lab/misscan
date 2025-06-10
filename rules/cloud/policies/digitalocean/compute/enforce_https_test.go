package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean/compute"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Load balancer forwarding rule using HTTP",
			input: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								EntryProtocol: misscanTypes.String("http", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer forwarding rule using HTTPS",
			input: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								EntryProtocol: misscanTypes.String("https", misscanTypes.NewTestMetadata()),
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
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.Rule().LongID() {
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
