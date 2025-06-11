package rds

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type RDS struct {
	Instances       []Instance
	Clusters        []Cluster
	Classic         Classic
	Snapshots       []Snapshots
	ParameterGroups []ParameterGroups
}

type Instance struct {
	Metadata                         misscanTypes.Metadata
	BackupRetentionPeriodDays        misscanTypes.IntValue
	ReplicationSourceARN             misscanTypes.StringValue
	PerformanceInsights              PerformanceInsights
	Encryption                       Encryption
	PublicAccess                     misscanTypes.BoolValue
	Engine                           misscanTypes.StringValue
	IAMAuthEnabled                   misscanTypes.BoolValue
	DeletionProtection               misscanTypes.BoolValue
	DBInstanceArn                    misscanTypes.StringValue
	StorageEncrypted                 misscanTypes.BoolValue
	DBInstanceIdentifier             misscanTypes.StringValue
	DBParameterGroups                []DBParameterGroupsList
	TagList                          []TagList
	EnabledCloudwatchLogsExports     []misscanTypes.StringValue
	EngineVersion                    misscanTypes.StringValue
	AutoMinorVersionUpgrade          misscanTypes.BoolValue
	MultiAZ                          misscanTypes.BoolValue
	PubliclyAccessible               misscanTypes.BoolValue
	LatestRestorableTime             misscanTypes.TimeValue
	ReadReplicaDBInstanceIdentifiers []misscanTypes.StringValue
}

type Cluster struct {
	Metadata                  misscanTypes.Metadata
	BackupRetentionPeriodDays misscanTypes.IntValue
	ReplicationSourceARN      misscanTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
	PublicAccess              misscanTypes.BoolValue
	Engine                    misscanTypes.StringValue
	LatestRestorableTime      misscanTypes.TimeValue
	AvailabilityZones         []misscanTypes.StringValue
	DeletionProtection        misscanTypes.BoolValue
	SkipFinalSnapshot         misscanTypes.BoolValue
}

type Snapshots struct {
	Metadata             misscanTypes.Metadata
	DBSnapshotIdentifier misscanTypes.StringValue
	DBSnapshotArn        misscanTypes.StringValue
	Encrypted            misscanTypes.BoolValue
	KmsKeyId             misscanTypes.StringValue
	SnapshotAttributes   []DBSnapshotAttributes
}

type Parameters struct {
	Metadata       misscanTypes.Metadata
	ParameterName  misscanTypes.StringValue
	ParameterValue misscanTypes.StringValue
}

type ParameterGroups struct {
	Metadata               misscanTypes.Metadata
	DBParameterGroupName   misscanTypes.StringValue
	DBParameterGroupFamily misscanTypes.StringValue
	Parameters             []Parameters
}

type DBSnapshotAttributes struct {
	Metadata        misscanTypes.Metadata
	AttributeValues []misscanTypes.StringValue
}

const (
	EngineAurora             = "aurora"
	EngineAuroraMysql        = "aurora-mysql"
	EngineAuroraPostgresql   = "aurora-postgresql"
	EngineMySQL              = "mysql"
	EnginePostgres           = "postgres"
	EngineCustomOracleEE     = "custom-oracle-ee"
	EngineOracleEE           = "oracle-ee"
	EngineOracleEECDB        = "oracle-ee-cdb"
	EngineOracleSE2          = "oracle-se2"
	EngineOracleSE2CDB       = "oracle-se2-cdb"
	EngineSQLServerEE        = "sqlserver-ee"
	EngineSQLServerSE        = "sqlserver-se"
	EngineSQLServerEX        = "sqlserver-ex"
	EngineSQLServerWEB       = "sqlserver-web"
	EngineMariaDB            = "mariadb"
	EngineCustomSQLServerEE  = "custom-sqlserver-ee"
	EngineCustomSQLServerSE  = "custom-sqlserver-se"
	EngineCustomSQLServerWEB = "custom-sqlserver-web"
)

type Encryption struct {
	Metadata       misscanTypes.Metadata
	EncryptStorage misscanTypes.BoolValue
	KMSKeyID       misscanTypes.StringValue
}

type ClusterInstance struct {
	Instance
	ClusterIdentifier misscanTypes.StringValue
}

type PerformanceInsights struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	KMSKeyID misscanTypes.StringValue
}

type DBParameterGroupsList struct {
	Metadata             misscanTypes.Metadata
	DBParameterGroupName misscanTypes.StringValue
	KMSKeyID             misscanTypes.StringValue
}

type TagList struct {
	Metadata misscanTypes.Metadata
}
