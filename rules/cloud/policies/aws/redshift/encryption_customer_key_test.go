package redshift

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/redshift"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    redshift.Redshift
		expected bool
	}{
		{
			name: "Redshift Cluster with encryption disabled",
			input: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-key", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Redshift Cluster missing KMS key",
			input: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Redshift Cluster encrypted with KMS key",
			input: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("some-key", misscanTypes.NewTestMetadata()),
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
			testState.AWS.Redshift = test.input
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
