package ssm

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ssm"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecretUseCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ssm.SSM
		expected bool
	}{
		{
			name: "AWS SSM missing KMS key",
			input: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SSM with default KMS key",
			input: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String(ssm.DefaultKMSKeyID, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SSM with proper KMS key",
			input: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("some-ok-key", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SSM = test.input
			results := CheckSecretUseCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecretUseCustomerKey.Rule().LongID() {
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
