package dynamodb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/dynamodb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckTableCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    dynamodb.DynamoDB
		expected bool
	}{
		{
			name: "Cluster encryption missing KMS key",
			input: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster encryption using default KMS key",
			input: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String(dynamodb.DefaultKMSKeyID, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster encryption using proper KMS key",
			input: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String("some-ok-key", misscanTypes.NewTestMetadata()),
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
			testState.AWS.DynamoDB = test.input
			results := CheckTableCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckTableCustomerKey.Rule().LongID() {
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
