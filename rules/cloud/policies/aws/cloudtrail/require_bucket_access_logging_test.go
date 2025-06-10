package cloudtrail

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBucketAccessLoggingRequired(t *testing.T) {
	tests := []struct {
		name     string
		inputCT  cloudtrail.CloudTrail
		inputS3  s3.S3
		expected bool
	}{
		{
			name: "Trail has bucket with logging enabled",
			inputCT: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						BucketName: misscanTypes.String("my-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			inputS3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("my-bucket", misscanTypes.NewTestMetadata()),
						Logging: s3.Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Trail has bucket without logging enabled",
			inputCT: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						BucketName: misscanTypes.String("my-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			inputS3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("my-bucket", misscanTypes.NewTestMetadata()),
						Logging: s3.Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.inputCT
			testState.AWS.S3 = test.inputS3
			results := checkBucketAccessLoggingRequired.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkBucketAccessLoggingRequired.Rule().LongID() {
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
