package gke

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableStackdriverMonitoring = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0052",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-stackdriver-monitoring",
		Summary:     "Stackdriver Monitoring should be enabled",
		Impact:      "Visibility will be reduced",
		Resolution:  "Enable StackDriver monitoring",
		Explanation: `StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableStackdriverMonitoringGoodExamples,
			BadExamples:         terraformEnableStackdriverMonitoringBadExamples,
			Links:               terraformEnableStackdriverMonitoringLinks,
			RemediationMarkdown: terraformEnableStackdriverMonitoringRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.MonitoringService.NotEqualTo("monitoring.googleapis.com/kubernetes") {
				results.Add(
					"Cluster does not use the monitoring.googleapis.com/kubernetes StackDriver monitoring service.",
					cluster.MonitoringService,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
