package rdb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptDBSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []rdb.DBSecurityGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_db_security_group" "example" {
				description = "memo"

				rule {
				  cidr_ip = "0.0.0.0/0"
				}
			}
`,
			expected: []rdb.DBSecurityGroup{{
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
			resource "nifcloud_db_security_group" "example" {
				rule {
				}
			}
`,

			expected: []rdb.DBSecurityGroup{{
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
			adapted := adaptDBSecurityGroups(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
