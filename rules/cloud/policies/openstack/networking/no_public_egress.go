package compute

import (
	"github.com/khulnasoft-lab/misscan/internal/cidr"
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoPublicEgress = rules.Register(
	scan.Rule{
		AVDID:       "AVD-OPNSTK-0004",
		Provider:    providers.OpenStackProvider,
		Service:     "networking",
		ShortCode:   "no-public-egress",
		Summary:     "A security group rule allows egress traffic to multiple public addresses",
		Impact:      "Potential exfiltration of data to the public internet",
		Resolution:  "Employ more restrictive security group rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			Links:               terraformNoPublicEgressLinks,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.OpenStack.Networking.SecurityGroups {
			for _, rule := range group.Rules {
				if rule.Metadata.IsUnmanaged() || rule.IsIngress.IsTrue() {
					continue
				}
				if cidr.IsPublic(rule.CIDR.Value()) && cidr.CountAddresses(rule.CIDR.Value()) > 1 {
					results.Add(
						"Security group rule allows egress to multiple public addresses.",
						rule.CIDR,
					)
				} else {
					results.AddPassed(rule)
				}
			}
		}
		return
	},
)
