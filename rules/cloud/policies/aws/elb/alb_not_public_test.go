package elb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAlbNotPublic(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer publicly accessible",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String(elb.TypeApplication, misscanTypes.NewTestMetadata()),
						Internal: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer internally accessible",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String(elb.TypeApplication, misscanTypes.NewTestMetadata()),
						Internal: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			results := CheckAlbNotPublic.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAlbNotPublic.Rule().LongID() {
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
