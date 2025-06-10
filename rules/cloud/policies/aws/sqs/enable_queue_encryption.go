package sqs

import (
	"github.com/khulnasoft-lab/misscan/internal/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableQueueEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0096",
		Provider:    providers.AWSProvider,
		Service:     "sqs",
		ShortCode:   "enable-queue-encryption",
		Summary:     "Unencrypted SQS queue.",
		Impact:      "The SQS queue messages could be read if compromised",
		Resolution:  "Turn on SQS Queue encryption",
		Explanation: `Queues should be encrypted to protect queue contents.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableQueueEncryptionGoodExamples,
			BadExamples:         terraformEnableQueueEncryptionBadExamples,
			Links:               terraformEnableQueueEncryptionLinks,
			RemediationMarkdown: terraformEnableQueueEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableQueueEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableQueueEncryptionBadExamples,
			Links:               cloudFormationEnableQueueEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableQueueEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, queue := range s.AWS.SQS.Queues {
			if queue.Metadata.IsUnmanaged() {
				continue
			}
			if queue.Encryption.KMSKeyID.IsEmpty() && queue.Encryption.ManagedEncryption.IsFalse() {
				results.Add(
					"Queue is not encrypted",
					queue.Encryption,
				)
			} else {
				results.AddPassed(&queue)
			}
		}
		return
	},
)
