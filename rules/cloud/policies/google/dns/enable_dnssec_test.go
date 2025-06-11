package dns

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/dns"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDnssec(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "DNSSec disabled and required when visibility explicitly public",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Visibility: misscanTypes.String("public", misscanTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DNSSec enabled",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Visibility: misscanTypes.String("public", misscanTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "DNSSec not required when private",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Visibility: misscanTypes.String("private", misscanTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			results := CheckEnableDnssec.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableDnssec.Rule().LongID() {
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
