package kms

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/kms"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRotateKmsKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "KMS key rotation period of 91 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              misscanTypes.NewTestMetadata(),
								RotationPeriodSeconds: misscanTypes.Int(7862400, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "KMS key rotation period of 30 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              misscanTypes.NewTestMetadata(),
								RotationPeriodSeconds: misscanTypes.Int(2592000, misscanTypes.NewTestMetadata()),
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
			testState.Google.KMS = test.input
			results := CheckRotateKmsKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRotateKmsKeys.Rule().LongID() {
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
