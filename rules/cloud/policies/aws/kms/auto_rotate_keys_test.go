package kms

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kms"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAutoRotateKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           misscanTypes.String("ENCRYPT_DECRYPT", misscanTypes.NewTestMetadata()),
						RotationEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation enabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           misscanTypes.String("ENCRYPT_DECRYPT", misscanTypes.NewTestMetadata()),
						RotationEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "SIGN_VERIFY KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           misscanTypes.String(kms.KeyUsageSignAndVerify, misscanTypes.NewTestMetadata()),
						RotationEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.KMS = test.input
			results := CheckAutoRotateKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAutoRotateKeys.Rule().LongID() {
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
