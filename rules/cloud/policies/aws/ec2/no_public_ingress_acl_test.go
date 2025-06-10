package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with wildcard address",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Type:     misscanTypes.String(ec2.TypeIngress, misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String(ec2.ActionAllow, misscanTypes.NewTestMetadata()),
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with private address",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Type:     misscanTypes.String(ec2.TypeIngress, misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String(ec2.ActionAllow, misscanTypes.NewTestMetadata()),
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.String("10.0.0.0/16", misscanTypes.NewTestMetadata()),
								},
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
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.Rule().LongID() {
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
