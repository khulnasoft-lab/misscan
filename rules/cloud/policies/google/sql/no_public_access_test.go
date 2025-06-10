package sql

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance settings set with IPv4 enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   misscanTypes.NewTestMetadata(),
								EnableIPv4: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled but public CIDR in authorized networks",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   misscanTypes.NewTestMetadata(),
								EnableIPv4: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name misscanTypes.StringValue
									CIDR misscanTypes.StringValue
								}{
									{
										CIDR: misscanTypes.String("0.0.0.0/0", misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled and private CIDR",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   misscanTypes.NewTestMetadata(),
								EnableIPv4: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name misscanTypes.StringValue
									CIDR misscanTypes.StringValue
								}{
									{
										CIDR: misscanTypes.String("10.0.0.1/24", misscanTypes.NewTestMetadata()),
									},
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
			testState.Google.SQL = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
