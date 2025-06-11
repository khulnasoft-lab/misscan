package storage

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/storage"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account minimum TLS version unspecified",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account minimum TLS version 1.0",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:          misscanTypes.NewTestMetadata(),
						MinimumTLSVersion: misscanTypes.String("TLS1_0", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account minimum TLS version 1.2",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:          misscanTypes.NewTestMetadata(),
						MinimumTLSVersion: misscanTypes.String("TLS1_2", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Storage = test.input
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
