package sqs

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sqs"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableQueueEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    sqs.SQS
		expected bool
	}{
		{
			name: "SQS Queue unencrypted",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          misscanTypes.NewTestMetadata(),
							ManagedEncryption: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID:          misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          misscanTypes.NewTestMetadata(),
							ManagedEncryption: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID:          misscanTypes.String("alias/aws/sqs", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          misscanTypes.NewTestMetadata(),
							ManagedEncryption: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID:          misscanTypes.String("some-ok-key", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          misscanTypes.NewTestMetadata(),
							ManagedEncryption: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID:          misscanTypes.String("", misscanTypes.NewTestMetadata()),
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
			testState.AWS.SQS = test.input
			results := CheckEnableQueueEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableQueueEncryption.Rule().LongID() {
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
