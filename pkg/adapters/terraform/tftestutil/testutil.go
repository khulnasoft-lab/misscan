package tftestutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/terraform/parser"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func CreateModulesFromSource(t *testing.T, source, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})
	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	require.NoError(t, p.ParseFS(t.Context(), "."))
	modules, err := p.EvaluateAll(t.Context())
	require.NoError(t, err)
	return modules
}
