package kubernetes

import (
	"context"
	"io"

	"github.com/khulnasoft-lab/misscan/pkg/scanners/generic"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/kubernetes/parser"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/options"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func NewScanner(opts ...options.ScannerOption) *generic.GenericScanner {
	return generic.NewScanner("Kubernetes", types.SourceKubernetes, generic.ParseFunc(parse), opts...)
}

func parse(ctx context.Context, r io.Reader, path string) (any, error) {
	return parser.Parse(ctx, r, path)
}
