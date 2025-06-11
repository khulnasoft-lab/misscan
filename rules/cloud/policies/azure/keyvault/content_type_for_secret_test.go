package keyvault

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/keyvault"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckContentTypeForSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Key vault secret content-type not specified",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    misscanTypes.NewTestMetadata(),
								ContentType: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Key vault secret content-type specified",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    misscanTypes.NewTestMetadata(),
								ContentType: misscanTypes.String("password", misscanTypes.NewTestMetadata()),
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
			testState.Azure.KeyVault = test.input
			results := CheckContentTypeForSecret.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckContentTypeForSecret.Rule().LongID() {
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
