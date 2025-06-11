package iam

import (
	"math"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func adaptPasswordPolicy(modules terraform.Modules) iam.PasswordPolicy {

	policy := iam.PasswordPolicy{
		Metadata:             misscanTypes.NewUnmanagedMetadata(),
		ReusePreventionCount: misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
		RequireLowercase:     misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		RequireUppercase:     misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		RequireNumbers:       misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		RequireSymbols:       misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		MaxAgeDays:           misscanTypes.IntDefault(math.MaxInt, misscanTypes.NewUnmanagedMetadata()),
		MinimumLength:        misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
	}

	passwordPolicies := modules.GetResourcesByType("aws_iam_account_password_policy")
	if len(passwordPolicies) == 0 {
		return policy
	}

	// aws only allows a single password policy resource
	policyBlock := passwordPolicies[0]

	policy.Metadata = policyBlock.GetMetadata()

	if attr := policyBlock.GetAttribute("require_lowercase_characters"); attr.IsNotNil() {
		policy.RequireLowercase = misscanTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireLowercase = misscanTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_uppercase_characters"); attr.IsNotNil() {
		policy.RequireUppercase = misscanTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireUppercase = misscanTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_numbers"); attr.IsNotNil() {
		policy.RequireNumbers = misscanTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireNumbers = misscanTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_symbols"); attr.IsNotNil() {
		policy.RequireSymbols = misscanTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireSymbols = misscanTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("password_reuse_prevention"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.ReusePreventionCount = misscanTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.ReusePreventionCount = misscanTypes.IntDefault(0, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("max_password_age"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MaxAgeDays = misscanTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MaxAgeDays = misscanTypes.IntDefault(math.MaxInt, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("minimum_password_length"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MinimumLength = misscanTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MinimumLength = misscanTypes.IntDefault(0, policyBlock.GetMetadata())
	}

	return policy
}
