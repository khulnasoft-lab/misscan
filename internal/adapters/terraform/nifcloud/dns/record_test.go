package dns

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/dns"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptRecords(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []dns.Record
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_dns_record" "example" {
				type    = "A"
				record  = "example-record"
			}
`,
			expected: []dns.Record{{
				Metadata: misscanTypes.NewTestMetadata(),
				Type:     misscanTypes.String("A", misscanTypes.NewTestMetadata()),
				Record:   misscanTypes.String("example-record", misscanTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_dns_record" "example" {
			}
`,

			expected: []dns.Record{{
				Metadata: misscanTypes.NewTestMetadata(),
				Type:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
				Record:   misscanTypes.String("", misscanTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRecords(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
