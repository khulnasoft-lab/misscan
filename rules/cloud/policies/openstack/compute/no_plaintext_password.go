package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoPlaintextPassword = rules.Register(
	scan.Rule{
		AVDID:       "AVD-OPNSTK-0001",
		Provider:    providers.OpenStackProvider,
		Service:     "compute",
		ShortCode:   "no-plaintext-password",
		Summary:     "No plaintext password for compute instance",
		Impact:      "Including a plaintext password could lead to compromised instance",
		Resolution:  "Do not use plaintext passwords in terraform files",
		Explanation: `Assigning a password to the compute instance using plaintext could lead to compromise; it would be preferable to use key-pairs as a login mechanism`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPlaintextPasswordGoodExamples,
			BadExamples:         terraformNoPlaintextPasswordBadExamples,
			Links:               terraformNoPlaintextPasswordLinks,
			RemediationMarkdown: terraformNoPlaintextPasswordRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.OpenStack.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.AdminPassword.IsNotEmpty() {
				results.Add(
					"Instance has admin password set.",
					instance.AdminPassword,
				)
			} else {
				results.AddPassed(instance)
			}
		}
		return
	},
)
