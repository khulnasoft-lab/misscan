package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/internal/rules"

	"github.com/khulnasoft-lab/misscan/pkg/providers"
)

var CheckRequireSupportRole = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0169",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.17"},
		},
		Service:    "iam",
		ShortCode:  "require-support-role",
		Summary:    "Missing IAM Role to allow authorized users to manage incidents with AWS Support.",
		Impact:     "Incident management is not possible without a support role.",
		Resolution: "Create an IAM role with the necessary permissions to manage incidents with AWS Support.",
		Explanation: `
By implementing least privilege for access control, an IAM Role will require an appropriate
IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {

		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				if policy.Builtin.IsTrue() && policy.Name.EqualTo("AWSSupportAccess") {
					results.AddPassed(&role)
					return
				}
			}
		}

		results.Add("Missing IAM support role.", misscanTypes.NewUnmanagedMetadata())
		return results
	},
)
