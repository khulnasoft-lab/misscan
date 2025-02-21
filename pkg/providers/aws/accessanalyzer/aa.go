package accessanalyzer

import "github.com/khulnasoft-lab/misscan/pkg/types"

type AccessAnalyzer struct {
	Analyzers []Analyzer
}

type Analyzer struct {
	Metadata types.Metadata
	ARN      types.StringValue
	Name     types.StringValue
	Active   types.BoolValue
	Findings []Findings
}

type Findings struct {
	Metadata types.Metadata
}
