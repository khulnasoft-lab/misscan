package bigquery

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/bigquery"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0046",
		Provider:    providers.GoogleProvider,
		Service:     "bigquery",
		ShortCode:   "no-public-access",
		Summary:     "BigQuery datasets should only be accessible within the organisation",
		Impact:      "Exposure of sensitive data to the public iniernet",
		Resolution:  "Configure access permissions with higher granularity",
		Explanation: `Using 'allAuthenticatedUsers' provides any GCP user - even those outside of your organisation - access to your BigQuery dataset.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, dataset := range s.Google.BigQuery.Datasets {
			for _, grant := range dataset.AccessGrants {
				if grant.SpecialGroup.EqualTo(bigquery.SpecialGroupAllAuthenticatedUsers) {
					results.Add(
						"Dataset grants access to all authenticated GCP users.",
						grant.SpecialGroup,
					)
				} else {
					results.AddPassed(&grant)
				}
			}
		}
		return
	},
)
