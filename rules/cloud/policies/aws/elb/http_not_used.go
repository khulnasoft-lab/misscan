package elb

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckHttpNotUsed = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0054",
		Provider:   providers.AWSProvider,
		Service:    "elb",
		ShortCode:  "http-not-used",
		Summary:    "Use of plain HTTP.",
		Impact:     "Your traffic is not protected",
		Resolution: "Switch to HTTPS to benefit from TLS security features",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformHttpNotUsedGoodExamples,
			BadExamples:         terraformHttpNotUsedBadExamples,
			Links:               terraformHttpNotUsedLinks,
			RemediationMarkdown: terraformHttpNotUsedRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			if !lb.Type.EqualTo(elb.TypeApplication) {
				continue
			}
			for _, listener := range lb.Listeners {
				if !listener.Protocol.EqualTo("HTTP") {
					results.AddPassed(&listener)
					continue
				}

				var hasRedirect bool
				for _, action := range listener.DefaultActions {
					if action.Type.EqualTo("redirect") {
						hasRedirect = true
						break
					}
				}
				if hasRedirect {
					results.AddPassed(&listener)
					break
				}

				results.Add(
					"Listener for application load balancer does not use HTTPS.",
					listener.Protocol,
				)
			}
		}
		return
	},
)
