package athena

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/athena"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) athena.Athena {
	return athena.Athena{
		Databases:  nil,
		Workgroups: getWorkGroups(cfFile),
	}
}
