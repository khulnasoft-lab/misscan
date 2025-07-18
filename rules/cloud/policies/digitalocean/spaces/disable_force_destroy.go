package spaces

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckDisableForceDestroy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-DIG-0009",
		Provider:    providers.DigitalOceanProvider,
		Service:     "spaces",
		ShortCode:   "disable-force-destroy",
		Summary:     "Force destroy is enabled on Spaces bucket which is dangerous",
		Impact:      "Accidental deletion of bucket objects",
		Resolution:  "Don't use force destroy on bucket configuration",
		Explanation: `Enabling force destroy on a Spaces bucket means that the bucket can be deleted without the additional check that it is empty. This risks important data being accidentally deleted by a bucket removal process.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDisableForceDestroyGoodExamples,
			BadExamples:         terraformDisableForceDestroyBadExamples,
			Links:               terraformDisableForceDestroyLinks,
			RemediationMarkdown: terraformDisableForceDestroyRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.DigitalOcean.Spaces.Buckets {
			if bucket.Metadata.IsUnmanaged() {
				continue
			}
			if bucket.ForceDestroy.IsTrue() {
				results.Add(
					"Bucket has force-destroy enabled.",
					bucket.ForceDestroy,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
