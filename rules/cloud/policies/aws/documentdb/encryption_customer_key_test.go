package documentdb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    documentdb.DocumentDB
		expected bool
	}{
		{
			name: "DocDB Cluster encryption missing KMS key",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB Instance encryption missing KMS key",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB Cluster and Instance encrypted with proper KMS keys",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								KMSKeyID: misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
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
			testState.AWS.DocumentDB = test.input
			results := CheckEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptionCustomerKey.Rule().LongID() {
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
