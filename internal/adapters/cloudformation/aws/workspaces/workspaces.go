package workspaces

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/workspaces"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: getWorkSpaces(cfFile),
	}
}
