package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableVolumeEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "unencrypted EBS volume",
			input: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "encrypted EBS volume",
			input: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			results := CheckEnableVolumeEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableVolumeEncryption.Rule().LongID() {
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
