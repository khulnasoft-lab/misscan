package gke

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableNetworkPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0056",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-network-policy",
		Summary:     "Network Policy should be enabled on GKE clusters",
		Impact:      "Unrestricted inter-cluster communication",
		Resolution:  "Enable network policy",
		Explanation: `Enabling a network policy allows the segregation of network traffic by namespace`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableNetworkPolicyGoodExamples,
			BadExamples:         terraformEnableNetworkPolicyBadExamples,
			Links:               terraformEnableNetworkPolicyLinks,
			RemediationMarkdown: terraformEnableNetworkPolicyRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.NetworkPolicy.Enabled.IsFalse() && !cluster.EnableAutpilot.IsTrue() {
				results.Add(
					"Cluster does not have a network policy enabled.",
					cluster.NetworkPolicy.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
