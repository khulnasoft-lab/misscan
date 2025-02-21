package database

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Database struct {
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	Metadata misscanTypes.Metadata
	Server
}

type MySQLServer struct {
	Metadata misscanTypes.Metadata
	Server
}

type PostgreSQLServer struct {
	Metadata misscanTypes.Metadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	Metadata             misscanTypes.Metadata
	LogCheckpoints       misscanTypes.BoolValue
	ConnectionThrottling misscanTypes.BoolValue
	LogConnections       misscanTypes.BoolValue
}

type Server struct {
	Metadata                  misscanTypes.Metadata
	EnableSSLEnforcement      misscanTypes.BoolValue
	MinimumTLSVersion         misscanTypes.StringValue
	EnablePublicNetworkAccess misscanTypes.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	Metadata misscanTypes.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	Metadata           misscanTypes.Metadata
	EmailAddresses     []misscanTypes.StringValue
	DisabledAlerts     []misscanTypes.StringValue
	EmailAccountAdmins misscanTypes.BoolValue
}

type ExtendedAuditingPolicy struct {
	Metadata        misscanTypes.Metadata
	RetentionInDays misscanTypes.IntValue
}

type FirewallRule struct {
	Metadata misscanTypes.Metadata
	StartIP  misscanTypes.StringValue
	EndIP    misscanTypes.StringValue
}
