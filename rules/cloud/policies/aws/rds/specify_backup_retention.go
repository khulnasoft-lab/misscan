package rds

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckBackupRetentionSpecified = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0077",
		Provider:    providers.AWSProvider,
		Service:     "rds",
		ShortCode:   "specify-backup-retention",
		Summary:     "RDS Cluster and RDS instance should have backup retention longer than default 1 day",
		Impact:      "Potential loss of data and short opportunity for recovery",
		Resolution:  "Explicitly set the retention period to greater than the default",
		Explanation: `RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSpecifyBackupRetentionGoodExamples,
			BadExamples:         terraformSpecifyBackupRetentionBadExamples,
			Links:               terraformSpecifyBackupRetentionLinks,
			RemediationMarkdown: terraformSpecifyBackupRetentionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationSpecifyBackupRetentionGoodExamples,
			BadExamples:         cloudFormationSpecifyBackupRetentionBadExamples,
			Links:               cloudFormationSpecifyBackupRetentionLinks,
			RemediationMarkdown: cloudFormationSpecifyBackupRetentionRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {

			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if !cluster.ReplicationSourceARN.IsEmpty() {
				continue
			}
			if cluster.BackupRetentionPeriodDays.LessThan(2) {
				results.Add(
					"Cluster has very low backup retention period.",
					cluster.BackupRetentionPeriodDays,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if !instance.ReplicationSourceARN.IsEmpty() {
				continue
			}
			if instance.BackupRetentionPeriodDays.LessThan(2) {
				results.Add(
					"Instance has very low backup retention period.",
					instance.BackupRetentionPeriodDays,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)
