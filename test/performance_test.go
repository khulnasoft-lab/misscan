package test

import (
	"context"
	"fmt"
	"io/fs"
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/scanners/terraform/parser"

	"github.com/khulnasoft-lab/misscan/pkg/rules"

	"github.com/khulnasoft-lab/misscan/pkg/scanners/terraform/executor"

	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func BenchmarkCalculate(b *testing.B) {

	f, err := createBadBlocks()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := parser.New(f, "", parser.OptionStopOnHCLError(true))
		if err := p.ParseFS(context.TODO(), "project"); err != nil {
			b.Fatal(err)
		}
		modules, _, err := p.EvaluateAll(context.TODO())
		if err != nil {
			b.Fatal(err)
		}
		_, _, _ = executor.New().Execute(modules)
	}
}

func createBadBlocks() (fs.FS, error) {

	files := make(map[string]string)

	files["/project/main.tf"] = `
module "something" {
	source = "../modules/problem"
}
`

	for _, rule := range rules.GetFrameworkRules() {
		if rule.Rule().Terraform == nil {
			continue
		}
		for i, bad := range rule.Rule().Terraform.BadExamples {
			filename := fmt.Sprintf("/modules/problem/%s-%d.tf", rule.Rule().LongID(), i)
			files[filename] = bad
		}
	}

	f := testutil.CreateFS(&testing.T{}, files)
	return f, nil
}
