package sam

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableApiAccessLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0113",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-api-access-logging",
		Summary:     "SAM API stages for V1 and V2 should have access logging enabled",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for API Gateway stages",
		Explanation: `API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-accesslogsetting",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableApiAccessLoggingGoodExamples,
			BadExamples:         cloudFormationEnableApiAccessLoggingBadExamples,
			Links:               cloudFormationEnableApiAccessLoggingLinks,
			RemediationMarkdown: cloudFormationEnableApiAccessLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.Metadata.IsUnmanaged() {
				continue
			}

			if api.AccessLogging.CloudwatchLogGroupARN.IsEmpty() {
				results.Add(
					"Access logging is not configured.",
					api.AccessLogging.CloudwatchLogGroupARN,
				)
			} else {
				results.AddPassed(&api)
			}
		}

		return
	},
)
