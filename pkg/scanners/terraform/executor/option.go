package executor

import (
	"github.com/khulnasoft-lab/misscan/pkg/rego"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
)

type Option func(s *Executor)

func OptionWithResultsFilter(f func(scan.Results) scan.Results) Option {
	return func(s *Executor) {
		s.resultsFilters = append(s.resultsFilters, f)
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(s *Executor) {
		s.workspaceName = workspaceName
	}
}

func OptionWithRegoScanner(s *rego.Scanner) Option {
	return func(e *Executor) {
		e.regoScanner = s
	}
}

func OptionWithScanRawConfig(b bool) Option {
	return func(e *Executor) {
		e.scanRawConfig = b
	}
}
