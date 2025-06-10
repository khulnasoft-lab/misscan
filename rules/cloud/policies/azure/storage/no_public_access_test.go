package storage

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/storage"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account container public access set to blob",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								PublicAccess: misscanTypes.String(storage.PublicAccessBlob, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account container public access set to container",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								PublicAccess: misscanTypes.String(storage.PublicAccessContainer, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account container public access set to off",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     misscanTypes.NewTestMetadata(),
								PublicAccess: misscanTypes.String(storage.PublicAccessOff, misscanTypes.NewTestMetadata()),
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
			testState.Azure.Storage = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
