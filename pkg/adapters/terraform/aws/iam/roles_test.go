package iam

import (
	"sort"
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptRoles(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Role
	}{
		{
			name: "policy",
			terraform: `
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id
  policy = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "s3.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "policy" {
	version = "2012-10-17"
	statement {
	  effect    = "Allow"
	  actions   = ["ec2:Describe*"]
	  resources = ["*"]
	}
  }
`,
			expected: []iam.Role{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("test_role", misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("test_policy", misscanTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "policy attachment",
			terraform: `
resource "aws_iam_role" "role" {
  name               = "test-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "policy" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}
`,
			expected: []iam.Role{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("test-role", misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("test-policy", misscanTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "inline policy",
			terraform: `
resource "aws_iam_role" "example" {
  name               = "test-role"
  
  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ec2:Describe*"]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
}
`,
			expected: []iam.Role{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("test-role", misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("my_inline_policy", misscanTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
						},
					},
				},
			},
		},
		{
			name: "with for_each",
			terraform: `
locals {
  roles = toset(["test-role1", "test-role2"])
}

resource "aws_iam_role" "this" {
  for_each           = local.roles
  name               = each.key
  assume_role_policy = "{}"
}

data "aws_iam_policy_document" "this" {
  for_each = local.roles
  version  = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "this" {
  for_each    = local.roles
  name        = format("%s-policy", each.key)
  description = "A test policy"
  policy      = data.aws_iam_policy_document.this[each.key].json
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each   = local.roles
  role       = aws_iam_role.this[each.key].name
  policy_arn = aws_iam_policy.this[each.key].arn
}
`,
			expected: []iam.Role{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("test-role1", misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("test-role1-policy", misscanTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("test-role2", misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("test-role2-policy", misscanTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "policy with condition",
			terraform: `
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id
  policy = false ? data.aws_iam_policy_document.s3_policy.json : data.aws_iam_policy_document.s3_policy_one.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = ""
}

data "aws_iam_policy_document" "s3_policy_one" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:CreateBucket"]
    resources = ["*"]
  }
}`,
			expected: []iam.Role{
				{
					Name: misscanTypes.String("test_role", misscanTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Name:    misscanTypes.String("test_policy", misscanTypes.NewTestMetadata()),
							Builtin: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Document: func() iam.Document {
								builder := iamgo.NewPolicyBuilder()
								sb := iamgo.NewStatementBuilder()
								sb.WithEffect(iamgo.EffectAllow)
								sb.WithActions([]string{"s3:PutObject"})
								sb.WithResources([]string{"*"})

								builder.WithStatement(sb.Build())

								return iam.Document{
									Parsed:   builder.Build(),
									Metadata: misscanTypes.NewTestMetadata(),
									IsOffset: true,
									HasRefs:  false,
								}
							}(),
						},
					},
				},
			},
		},
		{
			name: "attach AWS managed policy using ARN directly",
			terraform: `resource "aws_iam_role" "test" {
  name = "example-role"
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}`,
			expected: []iam.Role{
				{
					Name: misscanTypes.StringTest("example-role"),
					Policies: []iam.Policy{
						{
							Document: iam.Document{
								Parsed: s3FullAccessPolicyDocument,
							},
						},
					},
				},
			},
		},
		{
			name: "attach AWS managed policy using ARN from data source",
			terraform: `data "aws_iam_policy" "s3_full_access" {
  arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role" "test" {
  name = "example-role"
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = data.aws_iam_policy.s3_full_access.arn
}`,
			expected: []iam.Role{
				{
					Name: misscanTypes.StringTest("example-role"),
					Policies: []iam.Policy{
						{
							Document: iam.Document{
								Parsed: s3FullAccessPolicyDocument,
							},
						},
					},
				},
			},
		},
		{
			name: "attach AWS managed policy using data source with policy name",
			terraform: `data "aws_iam_policy" "s3_full_access" {
  name = "AmazonS3FullAccess"
}

resource "aws_iam_role" "test" {
  name = "example-role"
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = data.aws_iam_policy.s3_full_access.arn
}`,
			expected: []iam.Role{
				{
					Name: misscanTypes.StringTest("example-role"),
					Policies: []iam.Policy{
						{
							Name: misscanTypes.StringTest("AmazonS3FullAccess"),
							Document: iam.Document{
								Parsed: s3FullAccessPolicyDocument,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRoles(modules)
			sort.Slice(adapted, func(i, j int) bool {
				return adapted[i].Name.Value() < adapted[j].Name.Value()
			})
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
