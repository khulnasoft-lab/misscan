package codebuild

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/codebuild"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a CodeBuild instance
func Adapt(cfFile parser.FileContext) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: getProjects(cfFile),
	}
}
