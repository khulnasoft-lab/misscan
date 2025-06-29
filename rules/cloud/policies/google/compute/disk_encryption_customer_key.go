package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckDiskEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0034",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "disk-encryption-customer-key",
		Summary:     "Disks should be encrypted with customer managed encryption keys",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Use managed keys to encrypt disks.",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDiskEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformDiskEncryptionCustomerKeyBadExamples,
			Links:               terraformDiskEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformDiskEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, disk := range s.Google.Compute.Disks {
			if disk.Metadata.IsUnmanaged() {
				continue
			}
			if disk.Encryption.KMSKeyLink.IsEmpty() {
				results.Add(
					"Disk is not encrypted with a customer managed key.",
					disk.Encryption.KMSKeyLink,
				)
			} else {
				results.AddPassed(&disk)
			}
		}
		return
	},
)
