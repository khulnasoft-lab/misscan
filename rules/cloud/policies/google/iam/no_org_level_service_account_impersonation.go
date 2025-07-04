package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoOrgLevelServiceAccountImpersonation = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0009",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-org-level-service-account-impersonation",
		Summary:     "Users should not be granted service account access at the organization level",
		Impact:      "Privilege escalation, impersonation of any/all services",
		Resolution:  "Provide access at the service-level instead of organization-level, if required",
		Explanation: `Users with service account access at organization level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoOrgLevelServiceAccountImpersonationGoodExamples,
			BadExamples:         terraformNoOrgLevelServiceAccountImpersonationBadExamples,
			Links:               terraformNoOrgLevelServiceAccountImpersonationLinks,
			RemediationMarkdown: terraformNoOrgLevelServiceAccountImpersonationRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, org := range s.Google.IAM.Organizations {
			for _, member := range org.Members {
				if member.Metadata.IsUnmanaged() {
					continue
				}
				if member.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at organization level.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range org.Bindings {
				if binding.Metadata.IsUnmanaged() {
					continue
				}
				if binding.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at organization level.",
						binding.Role,
					)
				} else {
					results.AddPassed(&binding)
				}

			}
		}
		return
	},
)
