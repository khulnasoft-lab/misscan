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
		AVDID:       "AVD-KUBE-0001",
		Provider:    providers.KubernetesProvider,
		Service:     "network",
		ShortCode:   "no-public-ingress",
		Summary:     "Public ingress should not be allowed via network policies",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Remove public access except where explicitly required",
		Explanation: `You should not expose infrastructure to the public internet except where explicitly required`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, policy := range s.Kubernetes.NetworkPolicies {
			if policy.Metadata.IsUnmanaged() {
				continue
			}
			for _, source := range policy.Spec.Ingress.SourceCIDRs {
				if cidr.IsPublic(source.Value()) {
					results.Add(
						"Network policy allows ingress from the public internet.",
						source,
					)
				} else {
					results.AddPassed(source)
				}
			}
		}
		return
	},
)
