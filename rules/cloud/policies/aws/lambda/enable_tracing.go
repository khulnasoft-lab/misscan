package lambda

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/lambda"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableTracing = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0066",
		Provider:    providers.AWSProvider,
		Service:     "lambda",
		ShortCode:   "enable-tracing",
		Summary:     "Lambda functions should have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.`,
		Links: []string{
			"https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableTracingGoodExamples,
			BadExamples:         terraformEnableTracingBadExamples,
			Links:               terraformEnableTracingLinks,
			RemediationMarkdown: terraformEnableTracingRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableTracingGoodExamples,
			BadExamples:         cloudFormationEnableTracingBadExamples,
			Links:               cloudFormationEnableTracingLinks,
			RemediationMarkdown: cloudFormationEnableTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, function := range s.AWS.Lambda.Functions {
			if function.Metadata.IsUnmanaged() {
				continue
			}
			if function.Tracing.Mode.NotEqualTo(lambda.TracingModeActive) {
				results.Add(
					"Function does not have tracing enabled.",
					function.Tracing.Mode,
				)
			} else {
				results.AddPassed(&function)
			}
		}
		return
	},
)
