package ec2

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func adaptRequestedAMIs(modules terraform.Modules) []ec2.RequestedAMI {
	var res []ec2.RequestedAMI

	for _, block := range modules.GetDatasByType("aws_ami") {
		res = append(res, adaptRequestedAMI(block))
	}
	return res
}

func adaptRequestedAMI(block *terraform.Block) ec2.RequestedAMI {
	return ec2.RequestedAMI{
		Metadata: block.GetMetadata(),
		Owners:   block.GetAttribute("owners").AsStringValues(),
	}
}
