package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoPublicIp = rules.Register(
	scan.Rule{
		AVDID:      "AVD-OCI-0001",
		Provider:   providers.OracleProvider,
		Service:    "compute",
		ShortCode:  "no-public-ip",
		Summary:    "Compute instance requests an IP reservation from a public pool",
		Impact:     "The compute instance has the ability to be reached from outside",
		Resolution: "Reconsider the use of an public IP",
		Explanation: `Compute instance requests an IP reservation from a public pool

The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.`,
		Links: []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIpGoodExamples,
			BadExamples:         terraformNoPublicIpBadExamples,
			Links:               terraformNoPublicIpLinks,
			RemediationMarkdown: terraformNoPublicIpRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, reservation := range s.Oracle.Compute.AddressReservations {
			if reservation.Metadata.IsUnmanaged() {
				continue
			}
			if reservation.Pool.EqualTo("public-ippool") { // TODO: future improvement: we need to see what this IP is used for before flagging
				results.Add(
					"Reservation made for public IP address.",
					reservation.Pool,
				)
			} else {
				results.AddPassed(reservation)
			}
		}
		return
	},
)
