package msk

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/msk"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster client broker with plaintext encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     misscanTypes.NewTestMetadata(),
							ClientBroker: misscanTypes.String(msk.ClientBrokerEncryptionPlaintext, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with plaintext or TLS encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     misscanTypes.NewTestMetadata(),
							ClientBroker: misscanTypes.String(msk.ClientBrokerEncryptionTLSOrPlaintext, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with TLS encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     misscanTypes.NewTestMetadata(),
							ClientBroker: misscanTypes.String(msk.ClientBrokerEncryptionTLS, misscanTypes.NewTestMetadata()),
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
			testState.AWS.MSK = test.input
			results := CheckEnableInTransitEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableInTransitEncryption.Rule().LongID() {
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
