package keyvault

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/keyvault"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPurge(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Keyvault purge protection disabled",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                misscanTypes.NewTestMetadata(),
						EnablePurgeProtection:   misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: misscanTypes.Int(30, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled but soft delete retention period set to 3 days",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                misscanTypes.NewTestMetadata(),
						EnablePurgeProtection:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: misscanTypes.Int(3, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled and soft delete retention period set to 30 days",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                misscanTypes.NewTestMetadata(),
						EnablePurgeProtection:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: misscanTypes.Int(30, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.KeyVault = test.input
			results := CheckNoPurge.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPurge.Rule().LongID() {
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
