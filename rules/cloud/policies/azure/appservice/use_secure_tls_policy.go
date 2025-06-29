package appservice

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0006",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "Web App uses latest TLS version",
		Impact:      "The minimum TLS version for apps should be TLS1_2",
		Resolution:  "The TLS version being outdated and has known vulnerabilities",
		Explanation: `Use a more recent TLS/SSL policy for the App Service`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.Metadata.IsUnmanaged() {
				continue
			}
			if service.Site.MinimumTLSVersion.NotEqualTo("1.2") {
				results.Add(
					"App service does not require a secure TLS version.",
					service.Site.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
