package database

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableSslEnforcement = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0020",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "enable-ssl-enforcement",
		Summary:     "SSL should be enforced on database connections where applicable",
		Impact:      "Insecure connections could lead to data loss and other vulnerabilities",
		Resolution:  "Enable SSL enforcement",
		Explanation: `SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableSslEnforcementGoodExamples,
			BadExamples:         terraformEnableSslEnforcementBadExamples,
			Links:               terraformEnableSslEnforcementLinks,
			RemediationMarkdown: terraformEnableSslEnforcementRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
