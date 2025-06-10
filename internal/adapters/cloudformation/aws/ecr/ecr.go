package ecr

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecr"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ecr.ECR {
	return ecr.ECR{
		Repositories: getRepositories(cfFile),
	}
}
