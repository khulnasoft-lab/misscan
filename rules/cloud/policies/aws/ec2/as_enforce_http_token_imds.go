package ec2

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckASIMDSAccessRequiresToken = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0130",
		Aliases:    []string{"aws-autoscaling-enforce-http-token-imds"},
		Provider:   providers.AWSProvider,
		Service:    "ec2",
		ShortCode:  "enforce-launch-config-http-token-imds",
		Summary:    "aws_instance should activate session tokens for Instance Metadata Service.",
		Impact:     "Instance metadata service can be interacted with freely",
		Resolution: "Enable HTTP token requirement for IMDS",
		Explanation: `
IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
`,

		Links: []string{
			"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
		},

		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformASEnforceHttpTokenImdsGoodExamples,
			BadExamples:         terraformASEnforceHttpTokenImdsBadExamples,
			Links:               terraformASEnforceHttpTokenImdsLinks,
			RemediationMarkdown: terraformASEnforceHttpTokenImdsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudformationASEnforceHttpTokenImdsGoodExamples,
			BadExamples:         cloudformationASEnforceHttpTokenImdsBadExamples,
			Links:               cloudformationASEnforceHttpTokenImdsLinks,
			RemediationMarkdown: cloudformationASEnforceHttpTokenImdsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, configuration := range s.AWS.EC2.LaunchConfigurations {
			if !configuration.RequiresIMDSToken() && !configuration.HasHTTPEndpointDisabled() {
				results.Add(
					"Launch configuration does not require IMDS access to require a token",
					configuration.MetadataOptions.HttpTokens,
				)
			} else {
				results.AddPassed(&configuration)
			}
		}
		for _, instance := range s.AWS.EC2.LaunchTemplates {
			if !instance.RequiresIMDSToken() && !instance.HasHTTPEndpointDisabled() {
				results.Add(
					"Launch template does not require IMDS access to require a token",
					instance.MetadataOptions.HttpTokens,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return results
	},
)
