package elasticache

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableBackupRetention = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0050",
		Provider:    providers.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-backup-retention",
		Summary:     "Redis cluster should have backup retention turned on",
		Impact:      "Without backups of the redis cluster recovery is made difficult",
		Resolution:  "Configure snapshot retention for redis cluster",
		Explanation: `Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableBackupRetentionGoodExamples,
			BadExamples:         terraformEnableBackupRetentionBadExamples,
			Links:               terraformEnableBackupRetentionLinks,
			RemediationMarkdown: terraformEnableBackupRetentionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableBackupRetentionGoodExamples,
			BadExamples:         cloudFormationEnableBackupRetentionBadExamples,
			Links:               cloudFormationEnableBackupRetentionLinks,
			RemediationMarkdown: cloudFormationEnableBackupRetentionRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.ElastiCache.Clusters {
			if !cluster.Engine.EqualTo("redis") {
				continue
			}

			if cluster.NodeType.EqualTo("cache.t1.micro") {
				continue
			}

			if cluster.SnapshotRetentionLimit.EqualTo(0) {
				results.Add(
					"Cluster snapshot retention is not enabled.",
					cluster.SnapshotRetentionLimit,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
