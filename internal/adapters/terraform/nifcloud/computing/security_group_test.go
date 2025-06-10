package computing

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/computing"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []computing.SecurityGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_security_group" "example" {
				group_name = "example"
				description = "memo"
			}
			
			resource "nifcloud_security_group_rule" "example" {
				type                 = "IN"
				security_group_names = [nifcloud_security_group.example.group_name]
				from_port            = 22
				to_port              = 22
				protocol             = "TCP"
				description          = "memo"
				cidr_ip              = "1.2.3.4/32"
			}
`,
			expected: []computing.SecurityGroup{{
				Metadata:    misscanTypes.NewTestMetadata(),
				Description: misscanTypes.String("memo", misscanTypes.NewTestMetadata()),
				IngressRules: []computing.SecurityGroupRule{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						CIDR:        misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
						Description: misscanTypes.String("memo", misscanTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_security_group" "example" {
			}
			
			resource "nifcloud_security_group_rule" "example" {
				type                 = "IN"
				security_group_names = [nifcloud_security_group.example.group_name]
			}

`,

			expected: []computing.SecurityGroup{{
				Metadata:    misscanTypes.NewTestMetadata(),
				Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				IngressRules: []computing.SecurityGroupRule{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						CIDR:        misscanTypes.String("", misscanTypes.NewTestMetadata()),
						Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("nifcloud_security_group_rule")}
			adapted := sgAdapter.adaptSecurityGroups(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
