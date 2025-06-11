package storage

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/storage"
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
			name: "Members set to all authenticated users",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []misscanTypes.StringValue{
									misscanTypes.String("allAuthenticatedUsers", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Members set to all users",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Member:   misscanTypes.String("allUsers", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Members set to specific users",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []misscanTypes.StringValue{
									misscanTypes.String("user:jane@example.com", misscanTypes.NewTestMetadata()),
								},
							},
						},
						Members: []iam.Member{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Member:   misscanTypes.String("user:john@example.com", misscanTypes.NewTestMetadata()),
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
			testState.Google.Storage = test.input
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
