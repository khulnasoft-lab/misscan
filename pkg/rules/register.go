package rules

import (
	"github.com/khulnasoft-lab/misscan/internal/rules"
	"github.com/khulnasoft-lab/misscan/pkg/framework"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	ruleTypes "github.com/khulnasoft-lab/misscan/pkg/types/rules"
)

func Register(rule scan.Rule) ruleTypes.RegisteredRule {
	return rules.Register(rule)
}

func Deregister(rule ruleTypes.RegisteredRule) {
	rules.Deregister(rule)
}

func GetRegistered(fw ...framework.Framework) []ruleTypes.RegisteredRule {
	return rules.GetFrameworkRules(fw...)
}

func GetSpecRules(spec string) []ruleTypes.RegisteredRule {
	return rules.GetSpecRules(spec)
}
