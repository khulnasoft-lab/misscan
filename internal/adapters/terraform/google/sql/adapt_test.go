package sql

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sql.SQL
	}{
		{
			name: "default flags",
			terraform: `
			resource "google_sql_database_instance" "db" {
				database_version = "POSTGRES_12"
				settings {
					backup_configuration {
						enabled = true
					}
					ip_configuration {
						ipv4_enabled = false
						authorized_networks {
							value           = "108.12.12.0/24"
							name            = "internal"
						}
						require_ssl = true
					}
				}
			}
`,
			expected: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						IsReplica:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						DatabaseVersion: misscanTypes.String("POSTGRES_12", misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
							Flags: sql.Flags{
								Metadata:                        misscanTypes.NewTestMetadata(),
								LogMinDurationStatement:         misscanTypes.Int(-1, misscanTypes.NewTestMetadata()),
								ContainedDatabaseAuthentication: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CrossDBOwnershipChaining:        misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								LocalInFile:                     misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								LogCheckpoints:                  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								LogConnections:                  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								LogDisconnections:               misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								LogLockWaits:                    misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								LogMinMessages:                  misscanTypes.String("", misscanTypes.NewTestMetadata()),
								LogTempFileSize:                 misscanTypes.Int(-1, misscanTypes.NewTestMetadata()),
							},
							IPConfiguration: sql.IPConfiguration{
								Metadata:   misscanTypes.NewTestMetadata(),
								RequireTLS: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								EnableIPv4: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name misscanTypes.StringValue
									CIDR misscanTypes.StringValue
								}{
									{
										Name: misscanTypes.String("internal", misscanTypes.NewTestMetadata()),
										CIDR: misscanTypes.String("108.12.12.0/24", misscanTypes.NewTestMetadata()),
									},
								},
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

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []sql.DatabaseInstance
	}{
		{
			name: "all flags",
			terraform: `
resource "google_sql_database_instance" "backup_source_instance" {
  name             = "test-instance"
  database_version = "POSTGRES_11"

  project             = "test-project"
  region              = "europe-west6"
  deletion_protection = false
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = "test-network"
      require_ssl     = true
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_temp_files"
      value = "0"
    }
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
  }
}
                `,
			expected: []sql.DatabaseInstance{
				{
					Metadata:        misscanTypes.NewTestMetadata(),
					DatabaseVersion: misscanTypes.String("POSTGRES_11", misscanTypes.NewTestMetadata()),
					IsReplica:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					Settings: sql.Settings{
						Backups: sql.Backups{
							Enabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						Flags: sql.Flags{
							LogConnections:                  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							LogTempFileSize:                 misscanTypes.Int(0, misscanTypes.NewTestMetadata()),
							LogCheckpoints:                  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							LogDisconnections:               misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							LogLockWaits:                    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							ContainedDatabaseAuthentication: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							CrossDBOwnershipChaining:        misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							LocalInFile:                     misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							LogMinDurationStatement:         misscanTypes.Int(-1, misscanTypes.NewTestMetadata()),
							LogMinMessages:                  misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
						IPConfiguration: sql.IPConfiguration{
							EnableIPv4: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							RequireTLS: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "google_sql_database_instance" "backup_source_instance" {
		name             = "test-instance"
		database_version = "POSTGRES_11"
	  
		settings {
		  backup_configuration {
			enabled = true
		  }

		  ip_configuration {
			ipv4_enabled    = false
			require_ssl     = true
			authorized_networks {
				name            = "internal"
				value           = "108.12.12.0/24"
			}
		  }

		  database_flags {
			name  = "log_connections"
			value = "on"
		  }
		  database_flags {
			name  = "log_temp_files"
			value = "0"
		  }
		  database_flags {
			name  = "log_checkpoints"
			value = "on"
		  }
		  database_flags {
			name  = "log_disconnections"
			value = "on"
		  }
		  database_flags {
			name  = "log_lock_waits"
			value = "on"
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Instances, 1)
	instance := adapted.Instances[0]

	assert.Equal(t, 2, instance.Metadata.Range().GetStartLine())
	assert.Equal(t, 41, instance.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, instance.DatabaseVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, instance.DatabaseVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, instance.Settings.Metadata.Range().GetStartLine())
	assert.Equal(t, 40, instance.Settings.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, instance.Settings.Backups.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, instance.Settings.Backups.Metadata.Range().GetEndLine())

	assert.Equal(t, 8, instance.Settings.Backups.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, instance.Settings.Backups.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, instance.Settings.IPConfiguration.Metadata.Range().GetStartLine())
	assert.Equal(t, 18, instance.Settings.IPConfiguration.Metadata.Range().GetEndLine())

	assert.Equal(t, 12, instance.Settings.IPConfiguration.EnableIPv4.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, instance.Settings.IPConfiguration.EnableIPv4.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, instance.Settings.IPConfiguration.RequireTLS.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, instance.Settings.IPConfiguration.RequireTLS.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, instance.Settings.IPConfiguration.AuthorizedNetworks[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, instance.Settings.IPConfiguration.AuthorizedNetworks[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, instance.Settings.IPConfiguration.AuthorizedNetworks[0].CIDR.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, instance.Settings.IPConfiguration.AuthorizedNetworks[0].CIDR.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, instance.Settings.Flags.LogConnections.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, instance.Settings.Flags.LogConnections.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, instance.Settings.Flags.LogTempFileSize.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, instance.Settings.Flags.LogTempFileSize.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 34, instance.Settings.Flags.LogDisconnections.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, instance.Settings.Flags.LogDisconnections.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, instance.Settings.Flags.LogLockWaits.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 38, instance.Settings.Flags.LogLockWaits.GetMetadata().Range().GetEndLine())

}
