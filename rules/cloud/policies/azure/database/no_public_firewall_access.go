package database

import (
	"github.com/khulnasoft-lab/misscan/internal/cidr"
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoPublicFirewallAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0029",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "no-public-firewall-access",
		Summary:     "Ensure database firewalls do not permit public access",
		Impact:      "Publicly accessible databases could lead to compromised data",
		Resolution:  "Don't use wide ip ranges for the sql firewall",
		Explanation: `Azure services can be allowed access through the firewall using a start and end IP address of 0.0.0.0. No other end ip address should be combined with a start of 0.0.0.0`,
		Links: []string{
			"https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/firewall-rules/create-or-update",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicFirewallAccessGoodExamples,
			BadExamples:         terraformNoPublicFirewallAccessBadExamples,
			Links:               terraformNoPublicFirewallAccessLinks,
			RemediationMarkdown: terraformNoPublicFirewallAccessRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			for _, rule := range server.FirewallRules {
				if allowingAzureServices(rule) {
					continue
				}
				if (cidr.IsPublic(rule.StartIP.Value()) || cidr.IsPublic(rule.EndIP.Value())) && rule.StartIP.NotEqualTo(rule.EndIP.Value()) {
					results.Add(
						"Firewall rule allows public internet access to a database server.",
						rule.StartIP,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, rule := range server.FirewallRules {
				if allowingAzureServices(rule) {
					continue
				}
				if (cidr.IsPublic(rule.StartIP.Value()) || cidr.IsPublic(rule.EndIP.Value())) && rule.StartIP.NotEqualTo(rule.EndIP.Value()) {
					results.Add(
						"Firewall rule allows public internet access to a database server.",
						rule.StartIP,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			for _, rule := range server.FirewallRules {
				if allowingAzureServices(rule) {
					continue
				}
				if (cidr.IsPublic(rule.StartIP.Value()) || cidr.IsPublic(rule.EndIP.Value())) && rule.StartIP.NotEqualTo(rule.EndIP.Value()) {
					results.Add(
						"Firewall rule allows public internet access to a database server.",
						rule.StartIP,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			for _, rule := range server.FirewallRules {
				if allowingAzureServices(rule) {
					continue
				}
				if (cidr.IsPublic(rule.StartIP.Value()) || cidr.IsPublic(rule.EndIP.Value())) && rule.StartIP.NotEqualTo(rule.EndIP.Value()) {
					results.Add(
						"Firewall rule allows public internet access to a database server.",
						rule.StartIP,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)

func allowingAzureServices(rule database.FirewallRule) bool {
	return rule.StartIP.EqualTo("0.0.0.0") && rule.EndIP.EqualTo("0.0.0.0")
}
