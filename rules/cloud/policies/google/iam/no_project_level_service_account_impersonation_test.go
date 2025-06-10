package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoProjectLevelServiceAccountImpersonation(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Project member role set to service account user",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Role:     misscanTypes.String("roles/iam.serviceAccountUser", misscanTypes.NewTestMetadata()),
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
			name: "Project member role set to service account token creator",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Role:     misscanTypes.String("roles/iam.serviceAccountTokenCreator", misscanTypes.NewTestMetadata()),
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
			name: "Project members set to custom roles",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Role:     misscanTypes.String("roles/specific-role", misscanTypes.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Role:     misscanTypes.String("roles/specific-role", misscanTypes.NewTestMetadata()),
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
			testState.Google.IAM = test.input
			results := CheckNoProjectLevelServiceAccountImpersonation.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoProjectLevelServiceAccountImpersonation.Rule().LongID() {
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
