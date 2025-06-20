package sql

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckMysqlNoLocalInfile = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0026",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "mysql-no-local-infile",
		Summary:     "Disable local_infile setting in MySQL",
		Impact:      "Arbitrary files read by attackers when combined with a SQL injection vulnerability.",
		Resolution:  "Disable the local infile setting",
		Explanation: `Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.`,
		Links: []string{
			"https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformMysqlNoLocalInfileGoodExamples,
			BadExamples:         terraformMysqlNoLocalInfileBadExamples,
			Links:               terraformMysqlNoLocalInfileLinks,
			RemediationMarkdown: terraformMysqlNoLocalInfileRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyMySQL {
				continue
			}
			if instance.Settings.Flags.LocalInFile.IsTrue() {
				results.Add(
					"Database instance has local file read access enabled.",
					instance.Settings.Flags.LocalInFile,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
