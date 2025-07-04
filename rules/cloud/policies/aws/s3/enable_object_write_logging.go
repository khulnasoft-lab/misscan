package s3

import (
	"fmt"

	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableObjectWriteLogging = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0171",
		Provider:  providers.AWSProvider,
		Service:   "s3",
		ShortCode: "enable-object-write-logging",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"3.10"},
		},
		Summary:    "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets.",
		Impact:     "Difficult/impossible to audit bucket object/data changes.",
		Resolution: "Enable Object-level logging for S3 buckets.",
		Explanation: `
Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html",
		},
		Severity: severity.Low,
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableObjectWriteLoggingGoodExamples,
			BadExamples:         terraformEnableObjectWriteLoggingBadExamples,
			Links:               terraformEnableObjectWriteLoggingLinks,
			RemediationMarkdown: terraformEnableObjectWriteLoggingRemediationMarkdown,
		},
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if !bucket.Name.GetMetadata().IsResolvable() {
				continue
			}
			bucketName := bucket.Name.Value()
			var hasWriteLogging bool
			for _, trail := range s.AWS.CloudTrail.Trails {
				for _, selector := range trail.EventSelectors {
					if selector.ReadWriteType.EqualTo("ReadOnly") {
						continue
					}
					for _, dataResource := range selector.DataResources {
						if dataResource.Type.NotEqualTo("AWS::S3::Object") {
							continue
						}
						for _, partialARN := range dataResource.Values {
							partial := partialARN.Value()
							if partial == "arn:aws:s3" { // logging for all of s3 is enabled
								hasWriteLogging = true
								break
							}
							// the slash is important as it enables logging for objects inside bucket
							if partial == fmt.Sprintf("arn:aws:s3:::%s/", bucketName) {
								hasWriteLogging = true
								break
							}
						}
					}
				}
				if hasWriteLogging {
					break
				}
			}
			if !hasWriteLogging {
				results.Add(
					"Bucket does not have object-level write logging enabled",
					&bucket,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
