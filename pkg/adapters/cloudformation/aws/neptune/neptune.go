package neptune

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/neptune"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a Neptune instance
func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}
