package sql

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckPgLogCheckpoints = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0025",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-checkpoints",
		Summary:     "Ensure that logging of checkpoints is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable checkpoints logging.",
		Explanation: `Logging checkpoints provides useful diagnostic data, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CHECKPOINTS",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPgLogCheckpointsGoodExamples,
			BadExamples:         terraformPgLogCheckpointsBadExamples,
			Links:               terraformPgLogCheckpointsLinks,
			RemediationMarkdown: terraformPgLogCheckpointsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogCheckpoints.IsFalse() {
				results.Add(
					"Database instance is not configured to log checkpoints.",
					instance.Settings.Flags.LogCheckpoints,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
