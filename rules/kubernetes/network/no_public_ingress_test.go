package network

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/kubernetes"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    []kubernetes.NetworkPolicy
		expected bool
	}{
		{
			name: "Public source CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Spec: kubernetes.NetworkPolicySpec{
						Metadata: misscanTypes.NewTestMetadata(),
						Ingress: kubernetes.Ingress{
							Metadata: misscanTypes.NewTestMetadata(),
							SourceCIDRs: []misscanTypes.StringValue{
								misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Private source CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Spec: kubernetes.NetworkPolicySpec{
						Metadata: misscanTypes.NewTestMetadata(),
						Ingress: kubernetes.Ingress{
							Metadata: misscanTypes.NewTestMetadata(),
							SourceCIDRs: []misscanTypes.StringValue{
								misscanTypes.String("10.0.0.0/16", misscanTypes.NewTestMetadata()),
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
			testState.Kubernetes.NetworkPolicies = test.input
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
