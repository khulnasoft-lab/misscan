package workspaces

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/workspaces"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptWorkspace(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  workspaces.WorkSpace
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_workspaces_workspace" "example" {
				root_volume_encryption_enabled = true
				user_volume_encryption_enabled = true
		}
`,
			expected: workspaces.WorkSpace{
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
		{
			name: "defaults",
			terraform: `
			resource "aws_workspaces_workspace" "example" {
		}
`,
			expected: workspaces.WorkSpace{
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
						Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWorkspace(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_workspaces_workspace" "example" {
		root_volume_encryption_enabled = true
		user_volume_encryption_enabled = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.WorkSpaces, 1)
	workspace := adapted.WorkSpaces[0]

	assert.Equal(t, 2, workspace.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, workspace.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, workspace.RootVolume.Metadata.Range().GetStartLine())
	assert.Equal(t, 3, workspace.RootVolume.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, workspace.RootVolume.Encryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 3, workspace.RootVolume.Encryption.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, workspace.UserVolume.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, workspace.UserVolume.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, workspace.UserVolume.Encryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, workspace.UserVolume.Encryption.Metadata.Range().GetEndLine())
}
