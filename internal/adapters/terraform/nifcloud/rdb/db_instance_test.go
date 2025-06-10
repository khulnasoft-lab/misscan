package rdb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptDBInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []rdb.DBInstance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_db_instance" "example" {
				backup_retention_period = 2
				engine                  = "MySQL"
				engine_version          = "5.7.15"
				publicly_accessible     = false
				network_id              = "example-network"
			}
`,
			expected: []rdb.DBInstance{{
				Metadata:                  misscanTypes.NewTestMetadata(),
				BackupRetentionPeriodDays: misscanTypes.Int(2, misscanTypes.NewTestMetadata()),
				Engine:                    misscanTypes.String("MySQL", misscanTypes.NewTestMetadata()),
				EngineVersion:             misscanTypes.String("5.7.15", misscanTypes.NewTestMetadata()),
				NetworkID:                 misscanTypes.String("example-network", misscanTypes.NewTestMetadata()),
				PublicAccess:              misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_db_instance" "example" {
			}
`,

			expected: []rdb.DBInstance{{
				Metadata:                  misscanTypes.NewTestMetadata(),
				BackupRetentionPeriodDays: misscanTypes.Int(0, misscanTypes.NewTestMetadata()),
				Engine:                    misscanTypes.String("", misscanTypes.NewTestMetadata()),
				EngineVersion:             misscanTypes.String("", misscanTypes.NewTestMetadata()),
				NetworkID:                 misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
				PublicAccess:              misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDBInstances(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
