package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoFolderLevelDefaultServiceAccountAssignment(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Default service account enabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              misscanTypes.NewTestMetadata(),
										DefaultServiceAccount: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
										Member:                misscanTypes.String("proper@email.com", misscanTypes.NewTestMetadata()),
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
			name: "Default service account disabled but default account data provided",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              misscanTypes.NewTestMetadata(),
										DefaultServiceAccount: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										Member:                misscanTypes.String("123-compute@developer.gserviceaccount.com", misscanTypes.NewTestMetadata()),
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
			name: "Default service account disabled but default account data provided #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata:                      misscanTypes.NewTestMetadata(),
										IncludesDefaultServiceAccount: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										Members: []misscanTypes.StringValue{
											misscanTypes.String("123-compute@developer.gserviceaccount.com", misscanTypes.NewTestMetadata())},
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
			name: "Default service account disabled and proper account data provided",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              misscanTypes.NewTestMetadata(),
										DefaultServiceAccount: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										Member:                misscanTypes.String("proper@email.com", misscanTypes.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata:                      misscanTypes.NewTestMetadata(),
										IncludesDefaultServiceAccount: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
										Members: []misscanTypes.StringValue{
											misscanTypes.String("proper@account.com", misscanTypes.NewTestMetadata()),
										},
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
			results := CheckNoFolderLevelDefaultServiceAccountAssignment.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoFolderLevelDefaultServiceAccountAssignment.Rule().LongID() {
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
