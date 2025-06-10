package rds

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnablePerformanceInsightsEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Instance with performance insights disabled",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-kms-key", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "RDS Instance with performance insights enabled but missing KMS key",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata: misscanTypes.NewTestMetadata(),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: misscanTypes.NewTestMetadata(),
										Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
										KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
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
			name: "RDS Instance with performance insights enabled and KMS key provided",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-kms-key", misscanTypes.NewTestMetadata()),
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
			testState.AWS.RDS = test.input
			results := CheckEnablePerformanceInsightsEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != scan.StatusPassed && result.Rule().LongID() == CheckEnablePerformanceInsightsEncryption.Rule().LongID() {
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
