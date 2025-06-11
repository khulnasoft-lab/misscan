package s3

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableObjectReadLogging(t *testing.T) {
	tests := []struct {
		name       string
		s3         s3.S3
		cloudtrail cloudtrail.CloudTrail
		expected   bool
	}{
		{
			name: "S3 bucket with no cloudtrail logging",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								ReadWriteType: misscanTypes.String("WriteOnly", misscanTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("AWS::S3::Object", misscanTypes.NewTestMetadata()),
										Values: []misscanTypes.StringValue{
											misscanTypes.String("arn:aws:s3", misscanTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								ReadWriteType: misscanTypes.String("ReadOnly", misscanTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("AWS::S3::Object", misscanTypes.NewTestMetadata()),
										Values: []misscanTypes.StringValue{
											misscanTypes.String("arn:aws:s3", misscanTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								ReadWriteType: misscanTypes.String("All", misscanTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("AWS::S3::Object", misscanTypes.NewTestMetadata()),
										Values: []misscanTypes.StringValue{
											misscanTypes.String("arn:aws:s3", misscanTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								ReadWriteType: misscanTypes.String("All", misscanTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("AWS::S3::Object", misscanTypes.NewTestMetadata()),
										Values: []misscanTypes.StringValue{
											misscanTypes.String("arn:aws:s3:::test-bucket/", misscanTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								ReadWriteType: misscanTypes.String("All", misscanTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("AWS::S3::Object", misscanTypes.NewTestMetadata()),
										Values: []misscanTypes.StringValue{
											misscanTypes.String("arn:aws:s3:::test-bucket2/", misscanTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("test-bucket", misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      misscanTypes.NewTestMetadata(),
								ReadWriteType: misscanTypes.String("All", misscanTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Type:     misscanTypes.String("AWS::S3::Object", misscanTypes.NewTestMetadata()),
										Values: []misscanTypes.StringValue{
											misscanTypes.String("arn:aws:s3:::test-bucket", misscanTypes.NewTestMetadata()),
										},
									},
								},
							},
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
			testState.AWS.S3 = test.s3
			testState.AWS.CloudTrail = test.cloudtrail
			results := CheckEnableObjectReadLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableObjectReadLogging.Rule().LongID() {
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
