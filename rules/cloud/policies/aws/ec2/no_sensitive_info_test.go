package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoSensitiveInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Launch configuration with sensitive info in user data",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						UserData: misscanTypes.String(`
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						`, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration with no sensitive info in user data",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						UserData: misscanTypes.String(`
						export GREETING=hello
						`, misscanTypes.NewTestMetadata()),
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
			results := CheckNoSensitiveInfo.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoSensitiveInfo.Rule().LongID() {
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
