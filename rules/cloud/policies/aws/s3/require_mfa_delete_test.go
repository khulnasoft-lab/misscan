package s3

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireMFADelete(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "RequireMFADelete is not set",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  misscanTypes.NewTestMetadata(),
							Enabled:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							MFADelete: misscanTypes.BoolUnresolvable(misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "RequireMFADelete is false",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  misscanTypes.NewTestMetadata(),
							Enabled:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							MFADelete: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RequireMFADelete is true",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  misscanTypes.NewTestMetadata(),
							Enabled:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							MFADelete: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.S3 = test.input
			results := CheckRequireMFADelete.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireMFADelete.Rule().LongID() {
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
