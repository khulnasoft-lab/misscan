package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "EC2 volume missing KMS key",
			input: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EC2 volume encrypted with KMS key",
			input: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
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
			testState.AWS.EC2 = test.input
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
