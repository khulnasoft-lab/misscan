package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckInstancesDoNotHavePublicIPs = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0031",
		Provider:    providers.GoogleProvider,
		Service:     service,
		ShortCode:   "no-public-ip",
		Summary:     "Instances should not have public IP addresses",
		Impact:      "Direct exposure of an instance to the public internet",
		Resolution:  "Remove public IP",
		Explanation: `Instances should not be publicly exposed to the internet`,
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIpGoodExamples,
			BadExamples:         terraformNoPublicIpBadExamples,
			Links:               terraformNoPublicIpLinks,
			RemediationMarkdown: terraformNoPublicIpRemediationMarkdown,
		},
		Severity: severity.High,
		Links: []string{
			"https://cloud.google.com/compute/docs/ip-addresses#externaladdresses",
		},
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.HasPublicIP.IsTrue() {
					results.Add(
						"Instance has a public IP allocated.",
						networkInterface.HasPublicIP,
					)
				} else {
					results.AddPassed(&networkInterface)
				}
			}

		}
		return results
	},
)
