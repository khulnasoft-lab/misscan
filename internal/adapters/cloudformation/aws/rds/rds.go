package rds

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) rds.RDS {
	clusters, orphans := getClustersAndInstances(cfFile)
	return rds.RDS{
		Instances:       orphans,
		Clusters:        clusters,
		Classic:         getClassic(cfFile),
		ParameterGroups: getParameterGroups(cfFile),
		Snapshots:       nil,
	}
}
