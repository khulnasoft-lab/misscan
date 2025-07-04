package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableVPCFlowLogs = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0029",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-vpc-flow-logs",
		Summary:     "VPC flow logs should be enabled for all subnetworks",
		Impact:      "Limited auditing capability and awareness",
		Resolution:  "Enable VPC flow logs",
		Explanation: `VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableVpcFlowLogsGoodExamples,
			BadExamples:         terraformEnableVpcFlowLogsBadExamples,
			Links:               terraformEnableVpcFlowLogsLinks,
			RemediationMarkdown: terraformEnableVpcFlowLogsRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, network := range s.Google.Compute.Networks {
			for _, subnetwork := range network.Subnetworks {
				if subnetwork.EnableFlowLogs.IsFalse() {
					results.Add(
						"Subnetwork does not have VPC flow logs enabled.",
						subnetwork.EnableFlowLogs,
					)
				} else {
					results.AddPassed(&subnetwork)
				}
			}
		}
		return
	},
)
