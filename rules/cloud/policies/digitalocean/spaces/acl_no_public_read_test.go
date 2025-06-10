package spaces

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean/spaces"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAclNoPublicRead(t *testing.T) {
	tests := []struct {
		name     string
		input    spaces.Spaces
		expected bool
	}{
		{
			name: "Space bucket with public read ACL",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ACL:      misscanTypes.String("public-read", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket object with public read ACL",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ACL:      misscanTypes.String("private", misscanTypes.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								ACL:      misscanTypes.String("public-read", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket and bucket object with private ACL",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ACL:      misscanTypes.String("private", misscanTypes.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								ACL:      misscanTypes.String("private", misscanTypes.NewTestMetadata()),
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
			testState.DigitalOcean.Spaces = test.input
			results := CheckAclNoPublicRead.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAclNoPublicRead.Rule().LongID() {
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
