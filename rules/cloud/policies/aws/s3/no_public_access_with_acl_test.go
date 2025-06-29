package s3

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckForPublicACL(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "positive result",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ACL:      misscanTypes.String("public-read", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ACL:      misscanTypes.String("private", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.S3 = test.input
			results := CheckForPublicACL.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckForPublicACL.Rule().LongID() {
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
