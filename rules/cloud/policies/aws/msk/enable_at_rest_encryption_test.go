package msk

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/msk"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster with at rest encryption enabled",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EncryptionAtRest: msk.EncryptionAtRest{
							Metadata:  misscanTypes.NewTestMetadata(),
							KMSKeyARN: misscanTypes.String("foo-bar-key", misscanTypes.NewTestMetadata()),
							Enabled:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster with at rest encryption disabled",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.MSK = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.Rule().LongID() {
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
