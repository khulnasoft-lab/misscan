package workspaces

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/workspaces"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDiskEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    workspaces.WorkSpaces
		expected bool
	}{
		{
			name: "AWS Workspace with unencrypted root volume",
			input: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: misscanTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: misscanTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Workspace with unencrypted user volume",
			input: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: misscanTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: misscanTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},

		{
			name: "AWS Workspace with encrypted user and root volumes",
			input: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: misscanTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: misscanTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.WorkSpaces = test.input
			results := CheckEnableDiskEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableDiskEncryption.Rule().LongID() {
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
