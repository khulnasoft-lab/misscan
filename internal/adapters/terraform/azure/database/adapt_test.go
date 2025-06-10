package database

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  database.Database
	}{
		{
			name: "postgresql",
			terraform: `
			resource "azurerm_postgresql_server" "example" {
				name                = "example"
			  
				public_network_access_enabled    = true
				ssl_enforcement_enabled          = true
				ssl_minimal_tls_version_enforced = "TLS1_2"
			  }

			  resource "azurerm_postgresql_configuration" "example" {
				name                = "log_connections"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				value               = "on"
			  }

			  resource "azurerm_postgresql_configuration" "example" {
				name                = "log_checkpoints"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				value               = "on"
			  }

			  resource "azurerm_postgresql_configuration" "example" {
				name                = "connection_throttling"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				value               = "on"
			  }

			  resource "azurerm_postgresql_firewall_rule" "example" {
				name                = "office"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				start_ip_address    = "40.112.8.12"
				end_ip_address      = "40.112.8.12"
			  }
`,
			expected: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  misscanTypes.NewTestMetadata(),
							EnableSSLEnforcement:      misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							MinimumTLSVersion:         misscanTypes.String("TLS1_2", misscanTypes.NewTestMetadata()),
							EnablePublicNetworkAccess: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("40.112.8.12", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("40.112.8.12", misscanTypes.NewTestMetadata()),
								},
							},
						},
						Config: database.PostgresSQLConfig{
							Metadata:             misscanTypes.NewTestMetadata(),
							LogConnections:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							LogCheckpoints:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							ConnectionThrottling: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "mariadb",
			terraform: `
			resource "azurerm_mariadb_server" "example" {
				name                = "example-mariadb-server"
				location            = azurerm_resource_group.example.location
				resource_group_name = azurerm_resource_group.example.name
			  
				public_network_access_enabled = false
				ssl_enforcement_enabled       = true
			  }

			  resource "azurerm_mariadb_firewall_rule" "example" {
				name                = "test-rule"
				server_name         = azurerm_mariadb_server.example.name
				start_ip_address    = "40.112.0.0"
				end_ip_address      = "40.112.255.255"
			  }
`,
			expected: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  misscanTypes.NewTestMetadata(),
							EnableSSLEnforcement:      misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							MinimumTLSVersion:         misscanTypes.String("", misscanTypes.NewTestMetadata()),
							EnablePublicNetworkAccess: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("40.112.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("40.112.255.255", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "mysql",
			terraform: `
			resource "azurerm_mysql_server" "example" {
				public_network_access_enabled     = true
				ssl_enforcement_enabled           = true
				ssl_minimal_tls_version_enforced  = "TLS1_2"
			  }

			  resource "azurerm_mysql_firewall_rule" "example" {
				server_name         = azurerm_mysql_server.example.name
				start_ip_address    = "40.112.8.12"
				end_ip_address      = "40.112.8.12"
			  }
			`,
			expected: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  misscanTypes.NewTestMetadata(),
							EnableSSLEnforcement:      misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							MinimumTLSVersion:         misscanTypes.String("TLS1_2", misscanTypes.NewTestMetadata()),
							EnablePublicNetworkAccess: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("40.112.8.12", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("40.112.8.12", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ms sql",
			terraform: `
			resource "azurerm_mssql_server" "example" {
				name                          = "mssqlserver"
				minimum_tls_version           = "1.2"
				public_network_access_enabled = false
			  }

			  resource "azurerm_mssql_firewall_rule" "example" {
				name             = "FirewallRule1"
				server_id        = azurerm_mssql_server.example.id
				start_ip_address = "10.0.17.62"
				end_ip_address   = "10.0.17.62"
			  }

			  resource "azurerm_mssql_server_security_alert_policy" "example" {
				resource_group_name        = azurerm_resource_group.example.name
				server_name                = azurerm_mssql_server.example.name
				disabled_alerts = [
				  "Sql_Injection",
				  "Data_Exfiltration"
				]
				email_account_admins = true
				email_addresses = [
					"example@example.com"
				]
			  }

			  resource "azurerm_mssql_server_extended_auditing_policy" "example" {
				server_id                               = azurerm_mssql_server.example.id
				retention_in_days                       = 6
			  }
			`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  misscanTypes.NewTestMetadata(),
							MinimumTLSVersion:         misscanTypes.String("1.2", misscanTypes.NewTestMetadata()),
							EnablePublicNetworkAccess: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							EnableSSLEnforcement:      misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("10.0.17.62", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("10.0.17.62", misscanTypes.NewTestMetadata()),
								},
							},
						},
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        misscanTypes.NewTestMetadata(),
								RetentionInDays: misscanTypes.Int(6, misscanTypes.NewTestMetadata()),
							},
						},
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								EmailAddresses: []misscanTypes.StringValue{
									misscanTypes.String("example@example.com", misscanTypes.NewTestMetadata()),
								},
								DisabledAlerts: []misscanTypes.StringValue{
									misscanTypes.String("Sql_Injection", misscanTypes.NewTestMetadata()),
									misscanTypes.String("Data_Exfiltration", misscanTypes.NewTestMetadata()),
								},
								EmailAccountAdmins: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_postgresql_server" "example" {
		public_network_access_enabled    = true
		ssl_enforcement_enabled          = true
		ssl_minimal_tls_version_enforced = "TLS1_2"
	  }

	  resource "azurerm_postgresql_configuration" "example" {
		name                = "log_connections"
		server_name         = azurerm_postgresql_server.example.name
		value               = "on"
	  }

	  resource "azurerm_postgresql_configuration" "example" {
		name                = "log_checkpoints"
		server_name         = azurerm_postgresql_server.example.name
		value               = "on"
	  }

	  resource "azurerm_postgresql_configuration" "example" {
		name                = "connection_throttling"
		server_name         = azurerm_postgresql_server.example.name
		value               = "on"
	  }

	  resource "azurerm_postgresql_firewall_rule" "example" {
		name                = "office"
		server_name         = azurerm_postgresql_server.example.name
		start_ip_address    = "40.112.8.12"
		end_ip_address      = "40.112.8.12"
	  }

	  resource "azurerm_mariadb_server" "example" {	  
		public_network_access_enabled = false
		ssl_enforcement_enabled       = true
	  }

	  resource "azurerm_mariadb_firewall_rule" "example" {
		name                = "test-rule"
		server_name         = azurerm_mariadb_server.example.name
		start_ip_address    = "40.112.0.0"
		end_ip_address      = "40.112.255.255"
	  }

	  resource "azurerm_mysql_server" "example" {
		public_network_access_enabled     = true
		ssl_enforcement_enabled           = true
		ssl_minimal_tls_version_enforced  = "TLS1_2"
	  }

	  resource "azurerm_mysql_firewall_rule" "example" {
		server_name         = azurerm_mysql_server.example.name
		start_ip_address    = "40.112.8.12"
		end_ip_address      = "40.112.8.12"
	  }

	  resource "azurerm_mssql_server" "example" {
		name                          = "mssqlserver"
		public_network_access_enabled = false
		minimum_tls_version           = "1.2"
	  }

	  resource "azurerm_mssql_firewall_rule" "example" {
		name             = "FirewallRule1"
		server_id        = azurerm_mssql_server.example.id
		start_ip_address = "10.0.17.62"
		end_ip_address   = "10.0.17.62"
	  }

	  resource "azurerm_mssql_server_security_alert_policy" "example" {
		server_name                = azurerm_mssql_server.example.name
		disabled_alerts = [
		  "Sql_Injection",
		  "Data_Exfiltration"
		]
		email_account_admins = true
		email_addresses = [
			"example@example.com"
		]
	  }

	  resource "azurerm_mssql_server_extended_auditing_policy" "example" {
		server_id                               = azurerm_mssql_server.example.id
		retention_in_days                       = 6
	  }
	`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.PostgreSQLServers, 1)
	require.Len(t, adapted.MariaDBServers, 1)
	require.Len(t, adapted.MySQLServers, 1)
	require.Len(t, adapted.MSSQLServers, 1)

	postgres := adapted.PostgreSQLServers[0]
	mariadb := adapted.MariaDBServers[0]
	mysql := adapted.MySQLServers[0]
	mssql := adapted.MSSQLServers[0]

	assert.Equal(t, 2, postgres.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, postgres.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, postgres.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, postgres.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, postgres.EnableSSLEnforcement.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, postgres.EnableSSLEnforcement.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, postgres.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, postgres.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, postgres.Config.LogConnections.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, postgres.Config.LogConnections.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, postgres.Config.LogCheckpoints.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, postgres.Config.LogCheckpoints.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, postgres.Config.ConnectionThrottling.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, postgres.Config.ConnectionThrottling.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, postgres.FirewallRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 31, postgres.FirewallRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 29, postgres.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 29, postgres.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 30, postgres.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, postgres.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 33, mariadb.Metadata.Range().GetStartLine())
	assert.Equal(t, 36, mariadb.Metadata.Range().GetEndLine())

	assert.Equal(t, 34, mariadb.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, mariadb.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 35, mariadb.EnableSSLEnforcement.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, mariadb.EnableSSLEnforcement.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, mariadb.FirewallRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 43, mariadb.FirewallRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 41, mariadb.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 41, mariadb.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 42, mariadb.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, mariadb.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 45, mysql.Metadata.Range().GetStartLine())
	assert.Equal(t, 49, mysql.Metadata.Range().GetEndLine())

	assert.Equal(t, 46, mysql.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 46, mysql.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 47, mysql.EnableSSLEnforcement.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 47, mysql.EnableSSLEnforcement.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 48, mysql.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 48, mysql.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 51, mysql.FirewallRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 55, mysql.FirewallRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 53, mysql.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 53, mysql.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 54, mysql.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 54, mysql.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 57, mssql.Metadata.Range().GetStartLine())
	assert.Equal(t, 61, mssql.Metadata.Range().GetEndLine())

	assert.Equal(t, 59, mssql.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 59, mssql.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 60, mssql.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 60, mssql.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 63, mssql.FirewallRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 68, mssql.FirewallRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 66, mssql.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 66, mssql.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 67, mssql.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 67, mssql.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 70, mssql.SecurityAlertPolicies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 80, mssql.SecurityAlertPolicies[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 72, mssql.SecurityAlertPolicies[0].DisabledAlerts[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 75, mssql.SecurityAlertPolicies[0].DisabledAlerts[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 76, mssql.SecurityAlertPolicies[0].EmailAccountAdmins.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 76, mssql.SecurityAlertPolicies[0].EmailAccountAdmins.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 77, mssql.SecurityAlertPolicies[0].EmailAddresses[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 79, mssql.SecurityAlertPolicies[0].EmailAddresses[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 82, mssql.ExtendedAuditingPolicies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 85, mssql.ExtendedAuditingPolicies[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 84, mssql.ExtendedAuditingPolicies[0].RetentionInDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 84, mssql.ExtendedAuditingPolicies[0].RetentionInDays.GetMetadata().Range().GetEndLine())
}
