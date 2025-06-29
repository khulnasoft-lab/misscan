package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoIpForwarding = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0043",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-ip-forwarding",
		Summary:     "Instances should not have IP forwarding enabled",
		Impact:      "Instance can send/receive packets without the explicit instance address",
		Resolution:  "Disable IP forwarding",
		Explanation: `Disabling IP forwarding ensures the instance can only receive packets addressed to the instance and can only send packets with a source address of the instance.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoIpForwardingGoodExamples,
			BadExamples:         terraformNoIpForwardingBadExamples,
			Links:               terraformNoIpForwardingLinks,
			RemediationMarkdown: terraformNoIpForwardingRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.CanIPForward.IsTrue() {
				results.Add(
					"Instance has IP forwarding allowed.",
					instance.CanIPForward,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
