package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoUserGrantedPermissions(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Permissions granted to users",
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
										Member:   misscanTypes.String("user:test@example.com", misscanTypes.NewTestMetadata()),
										Role:     misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Members: []misscanTypes.StringValue{
											misscanTypes.String("user:test@example.com", misscanTypes.NewTestMetadata()),
										},
										Role: misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
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
			name: "Permissions granted to users #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Member:   misscanTypes.String("user:test@example.com", misscanTypes.NewTestMetadata()),
								Role:     misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Permissions granted to users #3",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Member:   misscanTypes.String("user:test@example.com", misscanTypes.NewTestMetadata()),
										Role:     misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
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
			name: "Permissions granted to users #4",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Members: []misscanTypes.StringValue{
											misscanTypes.String("user:test@example.com", misscanTypes.NewTestMetadata()),
										},
										Role: misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
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
			name: "Permissions granted on groups",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Member:   misscanTypes.String("group:test@example.com", misscanTypes.NewTestMetadata()),
								Role:     misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []misscanTypes.StringValue{
									misscanTypes.String("group:test@example.com", misscanTypes.NewTestMetadata()),
								},
								Role: misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
							},
						},
						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Members: []misscanTypes.StringValue{
											misscanTypes.String("group:test@example.com", misscanTypes.NewTestMetadata()),
										},
										Role: misscanTypes.String("some-role", misscanTypes.NewTestMetadata()),
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
			results := CheckNoUserGrantedPermissions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoUserGrantedPermissions.Rule().LongID() {
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
