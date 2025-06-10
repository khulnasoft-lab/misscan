package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPrivilegedServiceAccounts(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Service account granted owner role",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Role:     misscanTypes.String("roles/owner", misscanTypes.NewTestMetadata()),
								Member:   misscanTypes.String("serviceAccount:${google_service_account.test.email}", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Service account granted editor role",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Bindings: []iam.Binding{
											{
												Metadata: misscanTypes.NewTestMetadata(),
												Role:     misscanTypes.String("roles/editor", misscanTypes.NewTestMetadata()),
												Members: []misscanTypes.StringValue{
													misscanTypes.String("serviceAccount:${google_service_account.test.email}", misscanTypes.NewTestMetadata()),
												},
											},
										},
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
			name: "No service account with excessive privileges",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Members: []iam.Member{
											{
												Metadata: misscanTypes.NewTestMetadata(),
												Role:     misscanTypes.String("roles/owner", misscanTypes.NewTestMetadata()),
												Member:   misscanTypes.String("proper@email.com", misscanTypes.NewTestMetadata()),
											},
										},
										Bindings: []iam.Binding{
											{
												Metadata: misscanTypes.NewTestMetadata(),
												Role:     misscanTypes.String("roles/logging.logWriter", misscanTypes.NewTestMetadata()),
												Members: []misscanTypes.StringValue{
													misscanTypes.String("serviceAccount:${google_service_account.test.email}", misscanTypes.NewTestMetadata()),
												},
											},
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
			results := CheckNoPrivilegedServiceAccounts.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPrivilegedServiceAccounts.Rule().LongID() {
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
