package network

import (
	"github.com/khulnasoft-lab/misscan/internal/cidr"
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoPublicIngress = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0047",
		Provider:   providers.AzureProvider,
		Service:    "network",
		ShortCode:  "no-public-ingress",
		Summary:    "An inbound network security rule allows traffic from /0.",
		Impact:     "The port is exposed for ingress from the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Azure.Network.SecurityGroups {
			var failed bool
			for _, rule := range group.Rules {
				if rule.Outbound.IsTrue() || rule.Allow.IsFalse() {
					continue
				}
				for _, ip := range rule.SourceAddresses {
					// single public IPs acceptable to allow for well known IP addresses to be used
					if cidr.IsPublic(ip.Value()) && cidr.CountAddresses(ip.Value()) > 1 {
						failed = true
						results.Add(
							"Security group rule allows ingress from public internet.",
							ip,
						)
					}
				}
			}
			if !failed {
				results.AddPassed(&group)
			}
		}
		return
	},
)
