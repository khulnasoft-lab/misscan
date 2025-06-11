package sql

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SQL struct {
	Instances []DatabaseInstance
}

const (
	DatabaseFamilyMySQL     = "MYSQL"
	DatabaseFamilyPostgres  = "POSTGRES"
	DatabaseFamilySQLServer = "SQLSERVER"
)

const (
	DatabaseVersionMySQL_5_6                 = "MYSQL_5_6"
	DatabaseVersionMySQL_5_7                 = "MYSQL_5_7"
	DatabaseVersionMySQL_8_0                 = "MYSQL_8_0"
	DatabaseVersionPostgres_9_6              = "POSTGRES_9_6"
	DatabaseVersionPostgres_10               = "POSTGRES_10"
	DatabaseVersionPostgres_11               = "POSTGRES_11"
	DatabaseVersionPostgres_12               = "POSTGRES_12"
	DatabaseVersionPostgres_13               = "POSTGRES_13"
	DatabaseVersionSQLServer_2017_STANDARD   = "SQLSERVER_2017_STANDARD"
	DatabaseVersionSQLServer_2017_ENTERPRISE = "SQLSERVER_2017_ENTERPRISE"
	DatabaseVersionSQLServer_2017_EXPRESS    = "SQLSERVER_2017_EXPRESS"
	DatabaseVersionSQLServer_2017_WEB        = "SQLSERVER_2017_WEB"
)

type DatabaseInstance struct {
	Metadata        misscanTypes.Metadata
	DatabaseVersion misscanTypes.StringValue
	Settings        Settings
	IsReplica       misscanTypes.BoolValue
}

type Settings struct {
	Metadata        misscanTypes.Metadata
	Flags           Flags
	Backups         Backups
	IPConfiguration IPConfiguration
}
type Flags struct {
	Metadata                        misscanTypes.Metadata
	LogTempFileSize                 misscanTypes.IntValue
	LocalInFile                     misscanTypes.BoolValue
	ContainedDatabaseAuthentication misscanTypes.BoolValue
	CrossDBOwnershipChaining        misscanTypes.BoolValue
	LogCheckpoints                  misscanTypes.BoolValue
	LogConnections                  misscanTypes.BoolValue
	LogDisconnections               misscanTypes.BoolValue
	LogLockWaits                    misscanTypes.BoolValue
	LogMinMessages                  misscanTypes.StringValue // FATAL, PANIC, LOG, ERROR, WARN
	LogMinDurationStatement         misscanTypes.IntValue
}

type Backups struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type IPConfiguration struct {
	Metadata           misscanTypes.Metadata
	RequireTLS         misscanTypes.BoolValue
	SSLMode            misscanTypes.StringValue
	EnableIPv4         misscanTypes.BoolValue
	AuthorizedNetworks []struct {
		Name misscanTypes.StringValue
		CIDR misscanTypes.StringValue
	}
}
