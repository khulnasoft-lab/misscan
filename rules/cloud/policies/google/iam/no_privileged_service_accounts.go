package iam

import (
	"strings"

	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/rules"

	"github.com/khulnasoft-lab/misscan/pkg/providers"
)

var CheckNoPrivilegedServiceAccounts = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0007",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-privileged-service-accounts",
		Summary:     "Service accounts should not have roles assigned with excessive privileges",
		Impact:      "Cloud account takeover if a resource using a service account is compromised",
		Resolution:  "Limit service account access to minimal required set",
		Explanation: `Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/understanding-roles",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPrivilegedServiceAccountsGoodExamples,
			BadExamples:         terraformNoPrivilegedServiceAccountsBadExamples,
			Links:               terraformNoPrivilegedServiceAccountsLinks,
			RemediationMarkdown: terraformNoPrivilegedServiceAccountsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, member := range project.Members {
				if member.Metadata.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					} else {
						results.AddPassed(&member)
					}

				}
			}
			for _, binding := range project.Bindings {
				if binding.Metadata.IsUnmanaged() {
					continue
				}
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						} else {
							results.AddPassed(&binding)
						}

					}
				}
			}
		}
		for _, folder := range s.Google.IAM.AllFolders() {
			for _, member := range folder.Members {
				if member.Metadata.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					} else {
						results.AddPassed(&member)
					}

				}
			}
			for _, binding := range folder.Bindings {
				if binding.Metadata.IsUnmanaged() {
					continue
				}
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						} else {
							results.AddPassed(member)
						}

					}
				}
			}

		}

		for _, org := range s.Google.IAM.Organizations {
			for _, member := range org.Members {
				if member.Metadata.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					} else {
						results.AddPassed(&member)
					}

				}
			}
			for _, binding := range org.Bindings {
				if binding.Metadata.IsUnmanaged() {
					continue
				}
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						} else {
							results.AddPassed(member)
						}

					}
				}
			}

		}

		return
	},
)

func isRolePrivileged(role string) bool {
	switch {
	case role == "roles/owner":
		return true
	case role == "roles/editor":
		return true
	case strings.HasSuffix(strings.ToLower(role), "admin"):
		return true
	}
	return false
}
