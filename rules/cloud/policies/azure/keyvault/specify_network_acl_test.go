package keyvault

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/keyvault"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSpecifyNetworkAcl(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Network ACL default action set to allow",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      misscanTypes.NewTestMetadata(),
							DefaultAction: misscanTypes.String("Allow", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network ACL default action set to deny",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      misscanTypes.NewTestMetadata(),
							DefaultAction: misscanTypes.String("Deny", misscanTypes.NewTestMetadata()),
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
			results := CheckSpecifyNetworkAcl.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSpecifyNetworkAcl.Rule().LongID() {
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
