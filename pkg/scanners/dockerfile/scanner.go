package dockerfile

import (
	"github.com/khulnasoft-lab/misscan/pkg/scanners/dockerfile/parser"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/generic"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/options"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func NewScanner(opts ...options.ScannerOption) *generic.GenericScanner {
	return generic.NewScanner("Dockerfile", types.SourceDockerfile, generic.ParseFunc(parser.Parse), opts...)
}
