package iam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type PasswordPolicy struct {
	Metadata             misscanTypes.Metadata
	ReusePreventionCount misscanTypes.IntValue
	RequireLowercase     misscanTypes.BoolValue
	RequireUppercase     misscanTypes.BoolValue
	RequireNumbers       misscanTypes.BoolValue
	RequireSymbols       misscanTypes.BoolValue
	MaxAgeDays           misscanTypes.IntValue
	MinimumLength        misscanTypes.IntValue
}
