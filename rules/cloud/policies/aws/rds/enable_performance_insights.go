package rds

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnablePerformanceInsights = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0133",
		Provider:   providers.AWSProvider,
		Service:    "rds",
		ShortCode:  "enable-performance-insights",
		Summary:    "Enable Performance Insights to detect potential problems",
		Impact:     "Without adequate monitoring, performance related issues may go unreported and potentially lead to compromise.",
		Resolution: "Enable performance insights",
		Explanation: `Enabling Performance insights allows for greater depth in monitoring data.
		
For example, information about active sessions could help diagose a compromise or assist in the investigation`,
		Links: []string{
			"https://aws.amazon.com/rds/performance-insights/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnablePerformanceInsightsGoodExamples,
			BadExamples:         terraformEnablePerformanceInsightsBadExamples,
			Links:               terraformEnablePerformanceInsightsLinks,
			RemediationMarkdown: terraformEnablePerformanceInsightsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnablePerformanceInsightsGoodExamples,
			BadExamples:         cloudFormationEnablePerformanceInsightsBadExamples,
			Links:               cloudFormationEnablePerformanceInsightsLinks,
			RemediationMarkdown: cloudFormationEnablePerformanceInsightsRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				if instance.Metadata.IsUnmanaged() {
					continue
				}
				if instance.PerformanceInsights.Enabled.IsFalse() {
					results.Add(
						"Instance does not have performance insights enabled.",
						instance.PerformanceInsights.Enabled,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.PerformanceInsights.Enabled.IsFalse() {
				results.Add(
					"Instance does not have performance insights enabled.",
					instance.PerformanceInsights.Enabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)
