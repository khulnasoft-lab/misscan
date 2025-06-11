package database

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicFirewallAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MySQL server firewall allows public internet access",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("255.255.255.255", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server firewall allows single public internet access",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("8.8.8.8", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("8.8.8.8", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows public internet access",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("255.255.255.255", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server firewall allows public internet access",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("255.255.255.255", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MariaDB server firewall allows public internet access",
			input: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("255.255.255.255", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server firewall allows access to Azure services",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows access to Azure services",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server firewall allows access to Azure services",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MariaDB server firewall allows access to Azure services",
			input: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: misscanTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									StartIP:  misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
									EndIP:    misscanTypes.String("0.0.0.0", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Database = test.input
			results := CheckNoPublicFirewallAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicFirewallAccess.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
