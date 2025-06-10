package nas

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptNASInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []nas.NASInstance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_nas_instance" "example" {
				network_id = "example-network"
			}
`,
			expected: []nas.NASInstance{{
				Metadata:  misscanTypes.NewTestMetadata(),
				NetworkID: misscanTypes.String("example-network", misscanTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_nas_instance" "example" {
			}
`,

			expected: []nas.NASInstance{{
				Metadata:  misscanTypes.NewTestMetadata(),
				NetworkID: misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNASInstances(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
