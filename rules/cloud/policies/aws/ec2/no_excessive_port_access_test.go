package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoExcessivePortAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("-1", misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String("allow", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("all", misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String("allow", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with tcp protocol",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Protocol: misscanTypes.String("tcp", misscanTypes.NewTestMetadata()),
								Type:     misscanTypes.String("egress", misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String("allow", misscanTypes.NewTestMetadata()),
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
			testState.AWS.EC2 = test.input
			results := CheckNoExcessivePortAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoExcessivePortAccess.Rule().LongID() {
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
