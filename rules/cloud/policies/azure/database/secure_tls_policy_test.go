package database

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL server minimum TLS version 1.0",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          misscanTypes.NewTestMetadata(),
							MinimumTLSVersion: misscanTypes.String("1.0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server minimum TLS version 1.0",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          misscanTypes.NewTestMetadata(),
							MinimumTLSVersion: misscanTypes.String("TLS1_0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.0",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          misscanTypes.NewTestMetadata(),
							MinimumTLSVersion: misscanTypes.String("TLS1_0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server minimum TLS version 1.2",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          misscanTypes.NewTestMetadata(),
							MinimumTLSVersion: misscanTypes.String("1.2", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MySQL server minimum TLS version 1.2",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          misscanTypes.NewTestMetadata(),
							MinimumTLSVersion: misscanTypes.String("TLS1_2", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.2",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          misscanTypes.NewTestMetadata(),
							MinimumTLSVersion: misscanTypes.String("TLS1_2", misscanTypes.NewTestMetadata()),
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
			results := CheckSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecureTlsPolicy.Rule().LongID() {
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
