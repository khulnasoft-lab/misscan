package repositories

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckPrivate = rules.Register(
	scan.Rule{
		AVDID:      "AVD-GIT-0001",
		Provider:   providers.GitHubProvider,
		Service:    "repositories",
		ShortCode:  "private",
		Summary:    "Github repository shouldn't be public.",
		Impact:     "Anyone can read the contents of the GitHub repository and leak IP",
		Resolution: "Make sensitive or commercially important repositories private",
		Explanation: `Github repository should be set to be private.

You can do this by either setting <code>private</code> attribute to 'true' or <code>visibility</code> attribute to 'internal' or 'private'.`,
		Links: []string{
			"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility",
			"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility#about-internal-repositories",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPrivateGoodExamples,
			BadExamples:         terraformPrivateBadExamples,
			Links:               terraformPrivateLinks,
			RemediationMarkdown: terraformPrivateRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, repo := range s.GitHub.Repositories {
			if repo.Metadata.IsUnmanaged() {
				continue
			}
			if repo.Public.IsTrue() {
				results.Add(
					"Repository is public,",
					repo.Public,
				)
			} else {
				results.AddPassed(repo)
			}
		}
		return
	},
)
