package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/dns"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dns.DNS
	}{
		{
			name: "basic",
			terraform: `
resource "google_dns_managed_zone" "example" {
  name        = "example-zone"
  dns_name    = "example-${random_id.rnd.hex}.com."
  description = "Example DNS zone"
  labels = {
    foo = "bar"
  }
  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm = "rsasha1"
      key_type  = "keySigning"
    }
    default_key_specs {
      algorithm = "rsasha1"
      key_type  = "zoneSigning"
    }
  }
}
`,
			expected: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Visibility: misscanTypes.String("public", misscanTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Enabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  misscanTypes.NewTestMetadata(),
									Algorithm: misscanTypes.String("rsasha1", misscanTypes.NewTestMetadata()),
									KeyType:   misscanTypes.String("keySigning", misscanTypes.NewTestMetadata()),
								},
								{
									Metadata:  misscanTypes.NewTestMetadata(),
									Algorithm: misscanTypes.String("rsasha1", misscanTypes.NewTestMetadata()),
									KeyType:   misscanTypes.String("zoneSigning", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "google_dns_managed_zone" "example" {
		name        = "example-zone"
		dns_name    = "example-${random_id.rnd.hex}.com."

		dnssec_config {
		  state = "on"
		  default_key_specs {
			  algorithm = "rsasha1"
			  key_type = "keySigning"
		  }
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.ManagedZones, 1)
	zone := adapted.ManagedZones[0]

	assert.Equal(t, 2, zone.Metadata.Range().GetStartLine())
	assert.Equal(t, 13, zone.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, zone.DNSSec.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, zone.DNSSec.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, zone.DNSSec.DefaultKeySpecs[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 11, zone.DNSSec.DefaultKeySpecs[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 9, zone.DNSSec.DefaultKeySpecs[0].Algorithm.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, zone.DNSSec.DefaultKeySpecs[0].Algorithm.GetMetadata().Range().GetEndLine())
}
