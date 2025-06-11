package computing

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/computing"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []computing.Instance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_instance" "my_example" {
				security_group  = "example-security-group"
				network_interface  {
					network_id    = "net-COMMON_PRIVATE"
				}
			}
`,
			expected: []computing.Instance{{
				Metadata:      misscanTypes.NewTestMetadata(),
				SecurityGroup: misscanTypes.String("example-security-group", misscanTypes.NewTestMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
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
			resource "nifcloud_instance" "my_example" {
				network_interface  {
				}
			}
`,

			expected: []computing.Instance{{
				Metadata:      misscanTypes.NewTestMetadata(),
				SecurityGroup: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
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
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
