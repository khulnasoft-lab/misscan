package ec2

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoDefaultVpc = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0101",
		Aliases:     []string{"aws-vpc-no-default-vpc"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-default-vpc",
		Summary:     "AWS best practice to not use the default VPC for workflows",
		Impact:      "The default VPC does not have critical security features applied",
		Resolution:  "Create a non-default vpc for resources to be created in",
		Explanation: `Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoDefaultVpcGoodExamples,
			BadExamples:         terraformNoDefaultVpcBadExamples,
			Links:               terraformNoDefaultVpcLinks,
			RemediationMarkdown: terraformNoDefaultVpcRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, def := range s.AWS.EC2.VPCs {
			if def.IsDefault.IsTrue() {
				results.Add(
					"Default VPC is used.",
					&def,
				)
			}
		}
		return
	},
)
