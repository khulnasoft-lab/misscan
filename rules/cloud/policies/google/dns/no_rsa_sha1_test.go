package dns

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/dns"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoRsaSha1(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "Zone signing using RSA SHA1 key",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: misscanTypes.NewTestMetadata(),
							DefaultKeySpecs: dns.KeySpecs{
								Metadata: misscanTypes.NewTestMetadata(),
								KeySigningKey: dns.Key{
									Metadata:  misscanTypes.NewTestMetadata(),
									Algorithm: misscanTypes.String("rsasha1", misscanTypes.NewTestMetadata()),
								},
								ZoneSigningKey: dns.Key{
									Metadata:  misscanTypes.NewTestMetadata(),
									Algorithm: misscanTypes.String("rsasha1", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Zone signing using RSA SHA512 key",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: misscanTypes.NewTestMetadata(),
							DefaultKeySpecs: dns.KeySpecs{
								Metadata: misscanTypes.NewTestMetadata(),
								KeySigningKey: dns.Key{
									Metadata:  misscanTypes.NewTestMetadata(),
									Algorithm: misscanTypes.String("rsasha512", misscanTypes.NewTestMetadata()),
								},
								ZoneSigningKey: dns.Key{
									Metadata:  misscanTypes.NewTestMetadata(),
									Algorithm: misscanTypes.String("rsasha512", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.DNS = test.input
			results := CheckNoRsaSha1.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoRsaSha1.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
