package database

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckPostgresConfigurationLogConnections = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0019",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-log-connections",
		Summary:     "Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No visibility of successful connections",
		Resolution:  "Enable connection logging",
		Explanation: `Postgresql can generate logs for successful connections to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPostgresConfigurationLogConnectionsGoodExamples,
			BadExamples:         terraformPostgresConfigurationLogConnectionsBadExamples,
			Links:               terraformPostgresConfigurationLogConnectionsLinks,
			RemediationMarkdown: terraformPostgresConfigurationLogConnectionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.Config.LogConnections.IsFalse() {
				results.Add(
					"Database server is not configured to log connections.",
					server.Config.LogConnections,
				)
			} else {
				results.AddPassed(&server.Config)
			}
		}
		return
	},
)
