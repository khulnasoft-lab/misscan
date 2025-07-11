package accessanalyzer

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/accessanalyzer"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) accessanalyzer.AccessAnalyzer {
	return accessanalyzer.AccessAnalyzer{
		Analyzers: adaptTrails(modules),
	}
}

func adaptTrails(modules terraform.Modules) []accessanalyzer.Analyzer {
	var analyzer []accessanalyzer.Analyzer

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_accessanalyzer_analyzer") {
			analyzer = append(analyzer, adaptAnalyzers(resource))
		}
	}
	return analyzer
}

func adaptAnalyzers(resource *terraform.Block) accessanalyzer.Analyzer {

	analyzerName := resource.GetAttribute("analyzer_name")
	analyzerNameAttr := analyzerName.AsStringValueOrDefault("", resource)

	arnAnalyzer := resource.GetAttribute("arn")
	arnAnalyzerAttr := arnAnalyzer.AsStringValueOrDefault("", resource)

	return accessanalyzer.Analyzer{
		Metadata: resource.GetMetadata(),
		Name:     analyzerNameAttr,
		ARN:      arnAnalyzerAttr,
		Active:   types.BoolDefault(false, resource.GetMetadata()),
	}
}
