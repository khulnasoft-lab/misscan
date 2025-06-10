package efs

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/efs"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) efs.EFS {
	return efs.EFS{
		FileSystems: getFileSystems(cfFile),
	}
}
