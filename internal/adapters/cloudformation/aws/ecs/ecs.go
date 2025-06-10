package ecs

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecs"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ecs.ECS {
	return ecs.ECS{
		Clusters:        getClusters(cfFile),
		TaskDefinitions: getTaskDefinitions(cfFile),
	}
}
