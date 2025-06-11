package storage

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/storage"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckQueueServicesLoggingEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account queue properties logging disabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      misscanTypes.NewTestMetadata(),
							EnableLogging: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
						Queues: []storage.Queue{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Name:     misscanTypes.String("my-queue", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account queue properties logging disabled with no queues",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      misscanTypes.NewTestMetadata(),
							EnableLogging: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Storage account queue properties logging enabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      misscanTypes.NewTestMetadata(),
							EnableLogging: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.Azure.Storage = test.input
			results := CheckQueueServicesLoggingEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckQueueServicesLoggingEnabled.Rule().LongID() {
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
