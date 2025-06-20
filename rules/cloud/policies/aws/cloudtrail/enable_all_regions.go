package cloudtrail

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableAllRegions = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0014",
		Provider:  providers.AWSProvider,
		Service:   "cloudtrail",
		ShortCode: "enable-all-regions",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"2.5"},
		},
		Summary:     "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed",
		Impact:      "Activity could be happening in your account in a different region",
		Resolution:  "Enable Cloudtrail in all regions",
		Explanation: `When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operating in.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAllRegionsGoodExamples,
			BadExamples:         terraformEnableAllRegionsBadExamples,
			Links:               terraformEnableAllRegionsLinks,
			RemediationMarkdown: terraformEnableAllRegionsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableAllRegionsGoodExamples,
			BadExamples:         cloudFormationEnableAllRegionsBadExamples,
			Links:               cloudFormationEnableAllRegionsLinks,
			RemediationMarkdown: cloudFormationEnableAllRegionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.IsMultiRegion.IsFalse() {
				results.Add(
					"Trail is not enabled across all regions.",
					trail.IsMultiRegion,
				)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)
