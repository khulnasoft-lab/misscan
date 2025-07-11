package container

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckConfiguredNetworkPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0043",
		Provider:    providers.AzureProvider,
		Service:     "container",
		ShortCode:   "configured-network-policy",
		Summary:     "Ensure AKS cluster has Network Policy configured",
		Impact:      "No network policy is protecting the AKS cluster",
		Resolution:  "Configure a network policy",
		Explanation: `The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.`,
		Links: []string{
			"https://kubernetes.io/docs/concepts/services-networking/network-policies",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformConfiguredNetworkPolicyGoodExamples,
			BadExamples:         terraformConfiguredNetworkPolicyBadExamples,
			Links:               terraformConfiguredNetworkPolicyLinks,
			RemediationMarkdown: terraformConfiguredNetworkPolicyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.NetworkProfile.NetworkPolicy.IsEmpty() {
				results.Add(
					"Kubernetes cluster does not have a network policy set.",
					cluster.NetworkProfile.NetworkPolicy,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
