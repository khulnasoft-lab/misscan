package nas

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngressnasSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    nas.NAS
		expected bool
	}{
		{
			name: "NIFCLOUD ingress nas security group rule with wildcard address",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						CIDRs: []misscanTypes.StringValue{
							misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress nas security group rule with private address",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						CIDRs: []misscanTypes.StringValue{
							misscanTypes.String("10.0.0.0/16", misscanTypes.NewTestMetadata()),
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
			testState.Nifcloud.NAS = test.input
			results := CheckNoPublicIngressNASSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngressNASSgr.Rule().LongID() {
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
