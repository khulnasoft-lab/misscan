package iam

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptPasswordPolicy(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.PasswordPolicy
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_account_password_policy" "strict" {
				minimum_password_length        = 8
				require_lowercase_characters   = true
				require_numbers                = true
				require_uppercase_characters   = true
				require_symbols                = true
				allow_users_to_change_password = true
				max_password_age               = 90
				password_reuse_prevention      = 3
			  }
`,
			expected: iam.PasswordPolicy{
				Metadata:             misscanTypes.NewTestMetadata(),
				ReusePreventionCount: misscanTypes.Int(3, misscanTypes.NewTestMetadata()),
				RequireLowercase:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				RequireUppercase:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				RequireNumbers:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				RequireSymbols:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				MaxAgeDays:           misscanTypes.Int(90, misscanTypes.NewTestMetadata()),
				MinimumLength:        misscanTypes.Int(8, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPasswordPolicy(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
