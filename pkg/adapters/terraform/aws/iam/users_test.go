package iam

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptUsers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.User
	}{
		{
			name: "policy",
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
							Document: defaultPolicyDocuemnt(false),
							Builtin:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "policy attachment",
			terraform: `
resource "aws_iam_user" "user" {
  name = "test-user"
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
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

resource "aws_iam_user_policy_attachment" "test-attach" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.policy.arn
}
`,
			expected: []iam.User{
				{
					Metadata:   misscanTypes.NewTestMetadata(),
					Name:       misscanTypes.String("test-user", misscanTypes.NewTestMetadata()),
					LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("test-policy", misscanTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
							Builtin:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "access key",
			terraform: `
resource "aws_iam_access_key" "lb" {
  user    = aws_iam_user.lb.name
  pgp_key = "keybase:some_person_that_exists"
  status  = "Active"
}

resource "aws_iam_user" "lb" {
  name = "loadbalafncer"
  path = "/system/"
}
`,
			expected: []iam.User{
				{
					Metadata:   misscanTypes.NewTestMetadata(),
					Name:       misscanTypes.String("loadbalafncer", misscanTypes.NewTestMetadata()),
					LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
					Policies:   nil,
					AccessKeys: []iam.AccessKey{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Active:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "access key with default status",
			terraform: `
resource "aws_iam_access_key" "lb" {
  user    = aws_iam_user.lb.name
  pgp_key = "keybase:some_person_that_exists"
}

resource "aws_iam_user" "lb" {
  name = "loadbalafncer"
  path = "/system/"
}
`,
			expected: []iam.User{
				{
					Metadata:   misscanTypes.NewTestMetadata(),
					Name:       misscanTypes.String("loadbalafncer", misscanTypes.NewTestMetadata()),
					LastAccess: misscanTypes.TimeUnresolvable(misscanTypes.NewTestMetadata()),
					Policies:   nil,
					AccessKeys: []iam.AccessKey{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Active:   misscanTypes.BoolDefault(true, misscanTypes.NewTestMetadata()),
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
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
