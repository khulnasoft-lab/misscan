package elb

import (
	"github.com/khulnasoft-lab/misscan/internal/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckAlbNotPublic = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0053",
		Provider:    providers.AWSProvider,
		Service:     "elb",
		ShortCode:   "alb-not-public",
		Summary:     "Load balancer is exposed to the internet.",
		Impact:      "The load balancer is exposed on the internet",
		Resolution:  "Switch to an internal load balancer or add a tfsecurity ignore",
		Explanation: `There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAlbNotPublicGoodExamples,
			BadExamples:         terraformAlbNotPublicBadExamples,
			Links:               terraformAlbNotPublicLinks,
			RemediationMarkdown: terraformAlbNotPublicRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			if lb.Metadata.IsUnmanaged() || lb.Type.EqualTo(elb.TypeGateway) {
				continue
			}
			if lb.Internal.IsFalse() {
				results.Add(
					"Load balancer is exposed publicly.",
					lb.Internal,
				)
			} else {
				results.AddPassed(&lb)
			}
		}
		return
	},
)
