package database

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckPostgresConfigurationLogCheckpoints = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0024",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-log-checkpoints",
		Summary:     "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No error and query logs generated on checkpoint",
		Resolution:  "Enable checkpoint logging",
		Explanation: `Postgresql can generate logs for checkpoints to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPostgresConfigurationLogCheckpointsGoodExamples,
			BadExamples:         terraformPostgresConfigurationLogCheckpointsBadExamples,
			Links:               terraformPostgresConfigurationLogCheckpointsLinks,
			RemediationMarkdown: terraformPostgresConfigurationLogCheckpointsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.Config.LogCheckpoints.IsFalse() {
				results.Add(
					"Database server is not configured to log checkpoints.",
					server.Config.LogCheckpoints,
				)
			} else {
				results.AddPassed(&server.Config)
			}
		}
		return
	},
)
