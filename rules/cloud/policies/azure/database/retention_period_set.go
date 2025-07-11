package database

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckRetentionPeriodSet = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0025",
		Provider:   providers.AzureProvider,
		Service:    "database",
		ShortCode:  "retention-period-set",
		Summary:    "Database auditing retention period should be longer than 90 days",
		Impact:     "Short logging retention could result in missing valuable historical information",
		Resolution: "Set retention periods of database auditing to greater than 90 days",
		Explanation: `When Auditing is configured for a SQL database, if the retention period is not set, the retention will be unlimited.

If the retention period is to be explicitly set, it should be set for no less than 90 days.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRetentionPeriodSetGoodExamples,
			BadExamples:         terraformRetentionPeriodSetBadExamples,
			Links:               terraformRetentionPeriodSetLinks,
			RemediationMarkdown: terraformRetentionPeriodSetRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.ExtendedAuditingPolicies {
				if policy.RetentionInDays.LessThan(90) && policy.RetentionInDays.NotEqualTo(0) {
					results.Add(
						"Server has a retention period of less than 90 days.",
						policy.RetentionInDays,
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
