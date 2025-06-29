package ec2

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckAddDescriptionToSecurityGroupRule = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0124",
		Aliases:    []string{"aws-vpc-add-description-to-security-group-rule"},
		Provider:   providers.AWSProvider,
		Service:    "ec2",
		ShortCode:  "add-description-to-security-group-rule",
		Summary:    "Missing description for security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups rules",
		Explanation: `Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupRuleGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupRuleBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupRuleLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRuleRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationAddDescriptionToSecurityGroupRuleGoodExamples,
			BadExamples:         cloudFormationAddDescriptionToSecurityGroupRuleBadExamples,
			Links:               cloudFormationAddDescriptionToSecurityGroupRuleLinks,
			RemediationMarkdown: cloudFormationAddDescriptionToSecurityGroupRuleRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range append(group.EgressRules, group.IngressRules...) {
				if rule.Description.IsEmpty() {
					results.Add(
						"Security group rule does not have a description.",
						rule.Description,
					)
				} else {
					results.AddPassed(&rule)
				}
			}

		}
		return
	},
)
