package rds

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptClusterStorageData(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Cluster with storage encryption disabled",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       misscanTypes.NewTestMetadata(),
							EncryptStorage: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID:       misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled but missing KMS key",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       misscanTypes.NewTestMetadata(),
							EncryptStorage: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID:       misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled and KMS key provided",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       misscanTypes.NewTestMetadata(),
							EncryptStorage: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID:       misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
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
			results := CheckEncryptClusterStorageData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptClusterStorageData.Rule().LongID() {
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
