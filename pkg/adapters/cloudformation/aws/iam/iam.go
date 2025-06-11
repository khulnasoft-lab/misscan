package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

// Adapt adapts an IAM instance
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		PasswordPolicy: iam.PasswordPolicy{
			Metadata:             misscanTypes.NewUnmanagedMetadata(),
			ReusePreventionCount: misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
			RequireLowercase:     misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			RequireUppercase:     misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			RequireNumbers:       misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			RequireSymbols:       misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			MaxAgeDays:           misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
			MinimumLength:        misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
		},
		Policies: getPolicies(cfFile),
		Groups:   getGroups(cfFile),
		Users:    getUsers(cfFile),
		Roles:    getRoles(cfFile),
	}
}
