package accessanalyzer

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/accessanalyzer"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func getAccessAnalyzer(ctx parser.FileContext) (analyzers []accessanalyzer.Analyzer) {

	analyzersList := ctx.GetResourcesByType("AWS::AccessAnalyzer::Analyzer")

	for _, r := range analyzersList {
		aa := accessanalyzer.Analyzer{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("AnalyzerName"),
			ARN:      r.StringDefault(""),
			Active:   types.BoolDefault(false, r.Metadata()),
		}

		analyzers = append(analyzers, aa)
	}
	return analyzers
}
