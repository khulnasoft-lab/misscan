package authorization

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/authorization"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitRoleActions(t *testing.T) {
	tests := []struct {
		name     string
		input    authorization.Authorization
		expected bool
	}{
		{
			name: "Wildcard action with all scopes",
			input: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Actions: []misscanTypes.StringValue{
									misscanTypes.String("*", misscanTypes.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []misscanTypes.StringValue{
							misscanTypes.String("/", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Wildcard action with specific scope",
			input: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Actions: []misscanTypes.StringValue{
									misscanTypes.String("*", misscanTypes.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []misscanTypes.StringValue{
							misscanTypes.String("proper-scope", misscanTypes.NewTestMetadata()),
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
			testState.Azure.Authorization = test.input
			results := CheckLimitRoleActions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitRoleActions.Rule().LongID() {
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
