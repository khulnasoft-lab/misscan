package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckRequireUppercaseInPasswords = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0061",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "require-uppercase-in-passwords",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"1.5"},
		},
		Summary:    "IAM Password policy should have requirement for at least one uppercase character.",
		Impact:     "Short, simple passwords are easier to compromise",
		Resolution: "Enforce longer, more complex passwords in the policy",
		Explanation: `,
IAM account password policies should ensure that passwords content including at least one uppercase character.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireUppercaseInPasswordsGoodExamples,
			BadExamples:         terraformRequireUppercaseInPasswordsBadExamples,
			Links:               terraformRequireUppercaseInPasswordsLinks,
			RemediationMarkdown: terraformRequireUppercaseInPasswordsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.Metadata.IsUnmanaged() {
			return
		}

		if policy.RequireUppercase.IsFalse() {
			results.Add(
				"Password policy does not require uppercase characters.",
				policy.RequireUppercase,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
