package network

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptVpnGateways(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.VpnGateway
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_vpn_gateway" "example" {
				security_group  = "example-security-group"
			}
`,
			expected: []network.VpnGateway{{
				Metadata:      misscanTypes.NewTestMetadata(),
				SecurityGroup: misscanTypes.String("example-security-group", misscanTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_vpn_gateway" "example" {
			}
`,

			expected: []network.VpnGateway{{
				Metadata:      misscanTypes.NewTestMetadata(),
				SecurityGroup: misscanTypes.String("", misscanTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptVpnGateways(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
