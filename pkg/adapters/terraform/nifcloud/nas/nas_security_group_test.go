package nas

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptNASSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []nas.NASSecurityGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_nas_security_group" "example" {
				description = "memo"

				rule {
				  cidr_ip = "0.0.0.0/0"
				}
			}
`,
			expected: []nas.NASSecurityGroup{{
				Metadata:    misscanTypes.NewTestMetadata(),
				Description: misscanTypes.String("memo", misscanTypes.NewTestMetadata()),
				CIDRs: []misscanTypes.StringValue{
					misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_nas_security_group" "example" {
				rule {
				}
			}
`,

			expected: []nas.NASSecurityGroup{{
				Metadata:    misscanTypes.NewTestMetadata(),
				Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				CIDRs: []misscanTypes.StringValue{
					misscanTypes.String("", misscanTypes.NewTestMetadata()),
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNASSecurityGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
