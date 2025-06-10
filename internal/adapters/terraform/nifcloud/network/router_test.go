package network

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptRouters(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.Router
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_router" "example" {
				security_group  = "example-security-group"
				network_interface  {
					network_id    = "net-COMMON_PRIVATE"
				}
			}
`,
			expected: []network.Router{{
				Metadata:      misscanTypes.NewTestMetadata(),
				SecurityGroup: misscanTypes.String("example-security-group", misscanTypes.NewTestMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						NetworkID: misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_router" "example" {
				network_interface  {
				}
			}
`,

			expected: []network.Router{{
				Metadata:      misscanTypes.NewTestMetadata(),
				SecurityGroup: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						NetworkID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRouters(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
