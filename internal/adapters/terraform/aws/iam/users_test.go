package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/liamg/iamgo"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptUsers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.User
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_user" "lb" {
				name = "loadbalancer"
				path = "/system/"
			  }
			  
			resource "aws_iam_user_policy" "policy" {
				name = "test"
				user = aws_iam_user.lb.name
	

				policy = jsonencode({
					Version = "2012-10-17"
					Statement = [
					  {
						Action = [
						  "ec2:Describe*",
						]
						Effect   = "Allow"
						Resource = "*"
					  },
					]
				  })
			  }
`,
			expected: []iam.User{
				{
					Metadata:   misscanTypes.NewTestMetadata(),
					Name:       misscanTypes.String("loadbalancer", misscanTypes.NewTestMetadata()),
					LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("test", misscanTypes.NewTestMetadata()),
							Document: func() iam.Document {

								builder := iamgo.NewPolicyBuilder()
								builder.WithVersion("2012-10-17")

								sb := iamgo.NewStatementBuilder()

								sb.WithEffect(iamgo.EffectAllow)
								sb.WithActions([]string{"ec2:Describe*"})
								sb.WithResources([]string{"*"})

								builder.WithStatement(sb.Build())

								return iam.Document{
									Parsed:   builder.Build(),
									Metadata: misscanTypes.NewTestMetadata(),
									IsOffset: false,
									HasRefs:  false,
								}
							}(),
							Builtin: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptUsers(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
