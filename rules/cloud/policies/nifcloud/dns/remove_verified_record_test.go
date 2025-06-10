package dns

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/dns"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckRemoveVerifiedRecord(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name:     "No records",
			input:    dns.DNS{},
			expected: false,
		},
		{
			name: "Some record",
			input: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String("A", misscanTypes.NewTestMetadata()),
						Record:   misscanTypes.String("some", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Some TXT record",
			input: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String("TXT", misscanTypes.NewTestMetadata()),
						Record:   misscanTypes.String("some", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},

		{
			name: "Verify TXT record",
			input: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Type:     misscanTypes.String("TXT", misscanTypes.NewTestMetadata()),
						Record:   misscanTypes.String(dns.ZoneRegistrationAuthTxt, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.DNS = test.input
			results := CheckRemoveVerifiedRecord.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRemoveVerifiedRecord.Rule().LongID() {
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
