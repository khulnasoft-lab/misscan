package spaces

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean/spaces"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDisableForceDestroy(t *testing.T) {
	tests := []struct {
		name     string
		input    spaces.Spaces
		expected bool
	}{
		{
			name: "Space bucket force destroy enabled",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata:     misscanTypes.NewTestMetadata(),
						ForceDestroy: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket force destroy disabled",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata:     misscanTypes.NewTestMetadata(),
						ForceDestroy: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			results := CheckDisableForceDestroy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDisableForceDestroy.Rule().LongID() {
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
