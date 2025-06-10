package eks

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS Cluster with no secrets in the resources attribute",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Secrets:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute but no KMS key",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Secrets:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute and a KMS key",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Secrets:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-arn", misscanTypes.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckEncryptSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptSecrets.Rule().LongID() {
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
