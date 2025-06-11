package sns

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sns"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckTopicEncryptionUsesCMK(t *testing.T) {
	tests := []struct {
		name     string
		input    sns.SNS
		expected bool
	}{
		{
			name: "AWS SNS Topic without encryption",
			input: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String("alias/aws/sns", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String("some-ok-key", misscanTypes.NewTestMetadata()),
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
			testState.AWS.SNS = test.input
			results := CheckTopicEncryptionUsesCMK.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckTopicEncryptionUsesCMK.Rule().LongID() {
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
