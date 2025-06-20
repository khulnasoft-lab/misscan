package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/framework"

	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/rules"

	"github.com/khulnasoft-lab/misscan/pkg/providers"
)

var CheckLimitUserAccessKeys = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0167",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.13"},
		},
		Service:    "iam",
		ShortCode:  "limit-user-access-keys",
		Summary:    "No user should have more than one active access key.",
		Impact:     "Widened scope for compromise.",
		Resolution: "Limit the number of active access keys to one key per user.",
		Explanation: `
Multiple active access keys widens the scope for compromise.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, user := range s.AWS.IAM.Users {
			var countActive int
			for _, key := range user.AccessKeys {
				if key.Active.IsTrue() {
					countActive++
				}
			}
			if countActive > 1 {
				results.Add("User has more than one active access key", &user)
			} else {
				results.AddPassed(&user)
			}
		}
		return
	},
)
