package rds

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourcesByType("AWS::RDS::DBCluster") {
		cluster := rds.Cluster{
			Metadata:                  clusterResource.Metadata(),
			BackupRetentionPeriodDays: misscanTypes.IntDefault(1, clusterResource.Metadata()),
			ReplicationSourceARN:      misscanTypes.StringDefault("", clusterResource.Metadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: clusterResource.Metadata(),
				Enabled:  misscanTypes.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID: misscanTypes.StringDefault("", clusterResource.Metadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       clusterResource.Metadata(),
				EncryptStorage: misscanTypes.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID:       misscanTypes.StringDefault("", clusterResource.Metadata()),
			},
			PublicAccess:         misscanTypes.BoolDefault(false, clusterResource.Metadata()),
			Engine:               misscanTypes.StringDefault(rds.EngineAurora, clusterResource.Metadata()),
			LatestRestorableTime: misscanTypes.TimeUnresolvable(clusterResource.Metadata()),
			DeletionProtection:   misscanTypes.BoolDefault(false, clusterResource.Metadata()),
			SkipFinalSnapshot:    misscanTypes.BoolDefault(false, clusterResource.Metadata()),
		}

		if engineProp := clusterResource.GetProperty("Engine"); engineProp.IsString() {
			cluster.Engine = engineProp.AsStringValue()
		}

		if backupProp := clusterResource.GetProperty("BackupRetentionPeriod"); backupProp.IsInt() {
			cluster.BackupRetentionPeriodDays = backupProp.AsIntValue()
		}

		if replicaProp := clusterResource.GetProperty("SourceDBInstanceIdentifier"); replicaProp.IsString() {
			cluster.ReplicationSourceARN = replicaProp.AsStringValue()
		}

		if piProp := clusterResource.GetProperty("EnablePerformanceInsights"); piProp.IsBool() {
			cluster.PerformanceInsights.Enabled = piProp.AsBoolValue()
		}

		if insightsKeyProp := clusterResource.GetProperty("PerformanceInsightsKMSKeyId"); insightsKeyProp.IsString() {
			cluster.PerformanceInsights.KMSKeyID = insightsKeyProp.AsStringValue()
		}

		if encryptedProp := clusterResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			cluster.Encryption.EncryptStorage = encryptedProp.AsBoolValue()
		}

		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.Encryption.KMSKeyID = keyProp.AsStringValue()
		}

		clusters[clusterResource.ID()] = cluster
	}
	return clusters
}

func getClassic(ctx parser.FileContext) rds.Classic {
	return rds.Classic{
		DBSecurityGroups: getClassicSecurityGroups(ctx),
	}
}

func getClassicSecurityGroups(ctx parser.FileContext) (groups []rds.DBSecurityGroup) {
	for _, dbsgResource := range ctx.GetResourcesByType("AWS::RDS::DBSecurityGroup") {
		group := rds.DBSecurityGroup{
			Metadata: dbsgResource.Metadata(),
		}
		groups = append(groups, group)
	}
	return groups
}
