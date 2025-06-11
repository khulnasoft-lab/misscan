package eks

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicClusterAccessToCidr(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS Cluster with public access CIDRs actively set to open",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						PublicAccessCIDRs: []misscanTypes.StringValue{
							misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with public access enabled but private CIDRs",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						PublicAccessCIDRs: []misscanTypes.StringValue{
							misscanTypes.String("10.2.0.0/8", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "EKS Cluster with public access disabled and private CIDRs",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						PublicAccessCIDRs: []misscanTypes.StringValue{
							misscanTypes.String("10.2.0.0/8", misscanTypes.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckNoPublicClusterAccessToCidr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicClusterAccessToCidr.Rule().LongID() {
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
