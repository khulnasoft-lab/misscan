package ec2

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func TestAdaptAMIs(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected ec2.EC2
	}{
		{
			name: "AMI with single owner",
			src: `
data "aws_ami" "example" {
    owners = ["amazon"]
}`,
			expected: ec2.EC2{
				RequestedAMIs: []ec2.RequestedAMI{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Owners: misscanTypes.StringValueList{
							misscanTypes.StringTest("amazon"),
						}},
				},
			},
		},
		{
			name: "AMI with multiple owners",
			src: `
data "aws_ami" "example" {
    owners = ["amazon", "badguys"]
}`,
			expected: ec2.EC2{
				RequestedAMIs: []ec2.RequestedAMI{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Owners: misscanTypes.StringValueList{
							misscanTypes.StringTest("amazon"),
							misscanTypes.StringTest("badguys"),
						},
					},
				},
			},
		},
		{
			name: "AMI without owner",
			src: `
data "aws_ami" "example" {
    name = "test-ami"
}`,
			expected: ec2.EC2{
				RequestedAMIs: []ec2.RequestedAMI{
					{
						Metadata: misscanTypes.NewTestMetadata(),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, tt.src, ".tf")
			testutil.AssertDefsecEqual(t, tt.expected, Adapt(modules))
		})
	}
}
