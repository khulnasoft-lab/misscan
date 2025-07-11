package gke

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableAutoRepair = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0063",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-auto-repair",
		Summary:     "Kubernetes should have 'Automatic repair' enabled",
		Impact:      "Failing nodes will require manual repair.",
		Resolution:  "Enable automatic repair",
		Explanation: `Automatic repair will monitor nodes and attempt repair when a node fails multiple subsequent health checks`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAutoRepairGoodExamples,
			BadExamples:         terraformEnableAutoRepairBadExamples,
			Links:               terraformEnableAutoRepairLinks,
			RemediationMarkdown: terraformEnableAutoRepairRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			for _, nodePool := range cluster.NodePools {
				if nodePool.Management.EnableAutoRepair.IsFalse() {
					results.Add(
						"Node pool does not have auto-repair enabled.",
						nodePool.Management.EnableAutoRepair,
					)
				} else {
					results.AddPassed(&nodePool)
				}
			}
		}
		return
	},
)
