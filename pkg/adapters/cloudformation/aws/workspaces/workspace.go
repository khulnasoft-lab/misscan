package workspaces

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/workspaces"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

func getWorkSpaces(ctx parser.FileContext) (workSpaces []workspaces.WorkSpace) {
	for _, r := range ctx.GetResourcesByType("AWS::WorkSpaces::Workspace") {
		workspace := workspaces.WorkSpace{
			Metadata: r.Metadata(),
			RootVolume: workspaces.Volume{
				Metadata: r.Metadata(),
				Encryption: workspaces.Encryption{
					Metadata: r.Metadata(),
					Enabled:  r.GetBoolProperty("RootVolumeEncryptionEnabled"),
				},
			},
			UserVolume: workspaces.Volume{
				Metadata: r.Metadata(),
				Encryption: workspaces.Encryption{
					Metadata: r.Metadata(),
					Enabled:  r.GetBoolProperty("UserVolumeEncryptionEnabled"),
				},
			},
		}

		workSpaces = append(workSpaces, workspace)
	}
	return workSpaces
}
