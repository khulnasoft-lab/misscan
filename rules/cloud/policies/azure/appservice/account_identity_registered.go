package appservice

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckAccountIdentityRegistered = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0002",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "account-identity-registered",
		Summary:     "Web App has registration with AD enabled",
		Impact:      "Interaction between services can't easily be achieved without username/password",
		Resolution:  "Register the app identity with AD",
		Explanation: `Registering the identity used by an App with AD allows it to interact with other services without using username and password`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAccountIdentityRegisteredGoodExamples,
			BadExamples:         terraformAccountIdentityRegisteredBadExamples,
			Links:               terraformAccountIdentityRegisteredLinks,
			RemediationMarkdown: terraformAccountIdentityRegisteredRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.Metadata.IsUnmanaged() {
				continue
			}
			if service.Identity.Type.IsEmpty() {
				results.Add(
					"App service does not have an identity type.",
					service.Identity.Type,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
