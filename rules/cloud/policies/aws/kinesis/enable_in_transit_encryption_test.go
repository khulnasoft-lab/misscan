package kinesis

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kinesis"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    kinesis.Kinesis
		expected bool
	}{
		{
			name: "AWS Kinesis Stream with no encryption",
			input: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String("NONE", misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-key", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption but no key",
			input: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String(kinesis.EncryptionTypeKMS, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption and key",
			input: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String(kinesis.EncryptionTypeKMS, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-key", misscanTypes.NewTestMetadata()),
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
			testState.AWS.Kinesis = test.input
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
