package arm

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/arm"
	"github.com/khulnasoft-lab/misscan/pkg/rego"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/scanners"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/azure"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/azure/arm/parser"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/options"
	"github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/khulnasoft-lab/misscan/pkg/log"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	*rego.RegoScannerProvider
	opts   []options.ScannerOption
	logger *log.Logger
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		RegoScannerProvider: rego.NewRegoScannerProvider(opts...),
		opts:                opts,
		logger:              log.WithPrefix("azure-arm"),
	}
	for _, opt := range opts {
		opt(scanner)
	}
	return scanner
}

func (s *Scanner) Name() string {
	return "Azure ARM"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	p := parser.New(fsys)
	deployments, err := p.ParseFS(ctx, dir)
	if err != nil {
		return nil, err
	}

	return s.scanDeployments(ctx, deployments, fsys)
}

func (s *Scanner) scanDeployments(ctx context.Context, deployments []azure.Deployment, f fs.FS) (scan.Results, error) {

	var results scan.Results

	for _, deployment := range deployments {

		result, err := s.scanDeployment(ctx, deployment, f)
		if err != nil {
			return nil, err
		}
		results = append(results, result...)
	}

	return results, nil
}

func (s *Scanner) scanDeployment(ctx context.Context, deployment azure.Deployment, fsys fs.FS) (scan.Results, error) {
	state := arm.Adapt(ctx, deployment)

	rs, err := s.InitRegoScanner(fsys, s.opts)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	results, err := rs.ScanInput(ctx, types.SourceCloud, rego.Input{
		Path:     deployment.Metadata.Range().GetFilename(),
		FS:       fsys,
		Contents: state.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}

	return results, nil
}
