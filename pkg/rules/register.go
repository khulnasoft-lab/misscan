package rules

import (
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/types/rules"
)

func Register(rule scan.Rule, f scan.CheckFunc) rules.RegisteredRule {
	return Register(rule, f)
}

// Implement the missing function
func GetFrameworkRules(fw ...framework.Framework) []rules.RegisteredRule {
	// Placeholder implementation - replace with actual logic
	return []rules.RegisteredRule{}
}

func GetRegistered(fw ...framework.Framework) (registered []rules.RegisteredRule) {
	return GetFrameworkRules(fw...)
}