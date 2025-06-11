package msk

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/msk"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster with logging disabled",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: misscanTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: misscanTypes.NewTestMetadata(),
									Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: misscanTypes.NewTestMetadata(),
									Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: misscanTypes.NewTestMetadata(),
									Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster logging to S3",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: misscanTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: misscanTypes.NewTestMetadata(),
									Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: misscanTypes.NewTestMetadata(),
									Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: misscanTypes.NewTestMetadata(),
									Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
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
			testState.AWS.MSK = test.input
			results := CheckEnableLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogging.Rule().LongID() {
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
