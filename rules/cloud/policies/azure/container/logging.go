package container

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0040",
		Provider:    providers.AzureProvider,
		Service:     "container",
		ShortCode:   "logging",
		Summary:     "Ensure AKS logging to Azure Monitoring is Configured",
		Impact:      "Logging provides valuable information about access and usage",
		Resolution:  "Enable logging for AKS",
		Explanation: `Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformLoggingGoodExamples,
			BadExamples:         terraformLoggingBadExamples,
			Links:               terraformLoggingLinks,
			RemediationMarkdown: terraformLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.AddonProfile.OMSAgent.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have logging enabled via OMS Agent.",
					cluster.AddonProfile.OMSAgent.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
