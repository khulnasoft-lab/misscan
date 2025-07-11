package ec2

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultVpc(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "default AWS VPC",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:  types.NewTestMetadata(),
						IsDefault: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "vpc but not default AWS VPC",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:  types.NewTestMetadata(),
						IsDefault: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name:     "no default AWS VPC",
			input:    ec2.EC2{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EC2 = test.input
			results := CheckNoDefaultVpc.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoDefaultVpc.Rule().LongID() {
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
