package ec2

import (
	"fmt"

	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/rules"

	"github.com/khulnasoft-lab/misscan/pkg/providers"
)

var CheckNoSecretsInUserData = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0029",
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-secrets-in-user-data",
		Summary:     "User data for EC2 instances must not contain sensitive AWS keys",
		Impact:      "User data is visible through the AWS Management console",
		Resolution:  "Remove sensitive data from the EC2 instance user-data",
		Explanation: `EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoSecretsInUserDataGoodExamples,
			BadExamples:         terraformNoSecretsInUserDataBadExamples,
			Links:               terraformNoSecretsInUserDataLinks,
			RemediationMarkdown: terraformNoSecretsInUserDataRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoSecretsInUserDataGoodExamples,
			BadExamples:         cloudFormationNoSecretsInUserDataBadExamples,
			Links:               cloudFormationNoSecretsInUserDataLinks,
			RemediationMarkdown: cloudFormationNoSecretsInUserDataRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.AWS.EC2.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if result := scanner.Scan(instance.UserData.Value()); result.TransgressionFound {
				results.Add(
					fmt.Sprintf("Sensitive data found in instance user data: %s", result.Description),
					instance.UserData,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
