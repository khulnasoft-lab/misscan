package rules

import (
	"github.com/khulnasoft-lab/misscan/internal/rules"
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
)

func Register(rule scan.Rule, f scan.CheckFunc) rules.RegisteredRule {
	return rules.Register(rule, f)
}

func GetRegistered(fw ...framework.Framework) (registered []rules.RegisteredRule) {
	return rules.GetFrameworkRules(fw...)
}
