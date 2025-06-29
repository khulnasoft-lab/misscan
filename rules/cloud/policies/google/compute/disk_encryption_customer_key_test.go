package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDiskEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Disk missing KMS key link",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   misscanTypes.NewTestMetadata(),
							KMSKeyLink: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Disk with KMS key link provided",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   misscanTypes.NewTestMetadata(),
							KMSKeyLink: misscanTypes.String("kms-key-link", misscanTypes.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckDiskEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDiskEncryptionCustomerKey.Rule().LongID() {
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
