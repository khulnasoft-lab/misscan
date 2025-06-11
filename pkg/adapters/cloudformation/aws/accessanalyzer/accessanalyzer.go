package accessanalyzer

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/accessanalyzer"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an AccessAnalyzer instance
func Adapt(cfFile parser.FileContext) accessanalyzer.AccessAnalyzer {
	return accessanalyzer.AccessAnalyzer{
		Analyzers: getAccessAnalyzer(cfFile),
	}
}
