package s3

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0132",
		Provider:    providers.AWSProvider,
		Service:     "s3",
		ShortCode:   "encryption-customer-key",
		Summary:     "S3 encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformCheckEncryptionCustomerKeyBadExamples,
			Links:               terraformCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationCheckEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {

			if bucket.ACL.EqualTo("log-delivery-write", types.IgnoreCase) {
				// Log buckets don't support non AES256 encryption - this rule doesn't apply here
				// https://aws.amazon.com/premiumsupport/knowledge-center/s3-server-access-log-not-delivered/
				continue
			}
			if bucket.Encryption.KMSKeyId.IsEmpty() {
				results.Add(
					"Bucket does not encrypt data with a customer managed key.",
					bucket.Encryption.KMSKeyId,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
