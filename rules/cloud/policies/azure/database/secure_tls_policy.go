package database

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckSecureTlsPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0026",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "secure-tls-policy",
		Summary:     "Databases should have the minimum TLS set for connections",
		Impact:      "Outdated TLS policies increase exposure to known issues",
		Resolution:  "Use the most modern TLS policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSecureTlsPolicyGoodExamples,
			BadExamples:         terraformSecureTlsPolicyBadExamples,
			Links:               terraformSecureTlsPolicyLinks,
			RemediationMarkdown: terraformSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.MinimumTLSVersion.NotEqualTo("1.2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.MinimumTLSVersion.NotEqualTo("TLS1_2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.MinimumTLSVersion.NotEqualTo("TLS1_2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
