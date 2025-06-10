package network

import (
	"github.com/khulnasoft-lab/misscan/internal/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoCommonPrivateElasticLoadBalancer = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0019",
		Aliases:     []string{"nifcloud-network-no-common-private-elb"},
		Provider:    providers.NifcloudProvider,
		Service:     "network",
		ShortCode:   "no-common-private-elb",
		Summary:     "The elb has common private network",
		Impact:      "The common private network is shared with other users",
		Resolution:  "Use private LAN",
		Explanation: `When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.`,
		Links: []string{
			"https://pfs.nifcloud.com/service/plan.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoCommonPrivateElasticLoadBalancerGoodExamples,
			BadExamples:         terraformNoCommonPrivateElasticLoadBalancerBadExamples,
			Links:               terraformNoCommonPrivateElasticLoadBalancerLinks,
			RemediationMarkdown: terraformNoCommonPrivateElasticLoadBalancerRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, elb := range s.Nifcloud.Network.ElasticLoadBalancers {
			for _, ni := range elb.NetworkInterfaces {
				if ni.NetworkID.EqualTo("net-COMMON_PRIVATE") {
					results.Add(
						"The elb has common private network",
						ni.NetworkID,
					)
				} else {
					results.AddPassed(&ni)
				}
			}
		}
		return
	},
)
