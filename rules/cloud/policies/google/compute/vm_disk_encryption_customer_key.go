package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckVmDiskEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0033",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "vm-disk-encryption-customer-key",
		Summary:     "VM disks should be encrypted with Customer Supplied Encryption Keys",
		Impact:      "Using unmanaged keys does not allow for proper management",
		Resolution:  "Use managed keys ",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformVmDiskEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformVmDiskEncryptionCustomerKeyBadExamples,
			Links:               terraformVmDiskEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformVmDiskEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			for _, disk := range append(instance.BootDisks, instance.AttachedDisks...) {
				if disk.Encryption.KMSKeyLink.IsEmpty() {
					results.Add(
						"Instance disk encryption does not use a customer managed key.",
						disk.Encryption.KMSKeyLink,
					)
				} else {
					results.AddPassed(&disk)
				}
			}
		}
		return
	},
)
