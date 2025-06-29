package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoOrgLevelDefaultServiceAccountAssignment = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0008",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-org-level-default-service-account-assignment",
		Summary:     "Roles should not be assigned to default service accounts",
		Impact:      "Violation of principal of least privilege",
		Resolution:  "Use specialised service accounts for specific purposes.",
		Explanation: `Default service accounts should not be used - consider creating specialised service accounts for individual purposes.`,
		Links: []string{
			"",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoOrgLevelDefaultServiceAccountAssignmentGoodExamples,
			BadExamples:         terraformNoOrgLevelDefaultServiceAccountAssignmentBadExamples,
			Links:               terraformNoOrgLevelDefaultServiceAccountAssignmentLinks,
			RemediationMarkdown: terraformNoOrgLevelDefaultServiceAccountAssignmentRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, org := range s.Google.IAM.Organizations {
			for _, binding := range org.Bindings {
				if binding.Metadata.IsUnmanaged() {
					continue
				}
				if binding.IncludesDefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						binding.IncludesDefaultServiceAccount,
					)
				} else {
					for _, member := range binding.Members {
						if isMemberDefaultServiceAccount(member.Value()) {
							results.Add(
								"Role is assigned to a default service account at organisation level.",
								member,
							)
						} else {
							results.AddPassed(member)
						}

					}
				}
			}
			for _, member := range org.Members {
				if member.Metadata.IsUnmanaged() {
					continue
				}
				if isMemberDefaultServiceAccount(member.Member.Value()) {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						member.Member,
					)
				} else if member.DefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						member.DefaultServiceAccount,
					)
				} else {
					results.AddPassed(&member)
				}

			}
		}
		return
	},
)
