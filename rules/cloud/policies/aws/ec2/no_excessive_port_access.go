package ec2

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoExcessivePortAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0102",
		Aliases:     []string{"aws-vpc-no-excessive-port-access"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-excessive-port-access",
		Summary:     "An Network ACL rule allows ALL ports.",
		Impact:      "All ports exposed for ingressing/egressing data",
		Resolution:  "Set specific allowed ports",
		Explanation: `Ensure access to specific required ports is allowed, and nothing else.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoExcessivePortAccessGoodExamples,
			BadExamples:         terraformNoExcessivePortAccessBadExamples,
			Links:               terraformNoExcessivePortAccessLinks,
			RemediationMarkdown: terraformNoExcessivePortAccessRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoExcessivePortAccessGoodExamples,
			BadExamples:         cloudFormationNoExcessivePortAccessBadExamples,
			Links:               cloudFormationNoExcessivePortAccessLinks,
			RemediationMarkdown: cloudFormationNoExcessivePortAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, acl := range s.AWS.EC2.NetworkACLs {
			for _, rule := range acl.Rules {
				if rule.Action.EqualTo("allow") && rule.Protocol.EqualTo("-1") || rule.Protocol.EqualTo("all") {
					results.Add(
						"Network ACL rule allows access using ALL ports.",
						rule.Protocol,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
