package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_AdaptVPC(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "defined",
			terraform: `resource "aws_flow_log" "this" {
  vpc_id = aws_vpc.main.id
}
resource "aws_default_vpc" "default" {
  tags = {
    Name = "Default VPC"
  }
}

resource "aws_vpc" "main" {
  cidr_block = "4.5.6.7/32"
}

resource "aws_security_group" "example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"

  ingress {
    description = "Rule #1"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    cidr_blocks = ["1.2.3.4/32"]
  }
}

resource "aws_network_acl_rule" "example" {
  egress      = false
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  rule_action = "allow"
  cidr_block  = "10.0.0.0/16"
}

resource "aws_security_group_rule" "example" {
  type              = "ingress"
  description       = "Rule #2"
  security_group_id = aws_security_group.example.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks = [
    "1.2.3.4/32",
    "4.5.6.7/32",
  ]
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
			expected: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						IsDefault:       misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						ID:              misscanTypes.String("", misscanTypes.NewTestMetadata()),
						FlowLogsEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						IsDefault:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						ID:              misscanTypes.String("", misscanTypes.NewTestMetadata()),
						FlowLogsEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("Allow inbound HTTP traffic", misscanTypes.NewTestMetadata()),
						IsDefault:   misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						VPCID:       misscanTypes.String("", misscanTypes.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),

								Description: misscanTypes.String("Rule #1", misscanTypes.NewTestMetadata()),
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.String("4.5.6.7/32", misscanTypes.NewTestMetadata()),
								},
								FromPort: misscanTypes.IntTest(80),
								ToPort:   misscanTypes.IntTest(80),
								Protocol: misscanTypes.StringTest("tcp"),
							},
							{
								Metadata: misscanTypes.NewTestMetadata(),

								Description: misscanTypes.String("Rule #2", misscanTypes.NewTestMetadata()),
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
									misscanTypes.String("4.5.6.7/32", misscanTypes.NewTestMetadata()),
								},
								FromPort: misscanTypes.IntTest(22),
								ToPort:   misscanTypes.IntTest(22),
								Protocol: misscanTypes.StringTest("tcp"),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    misscanTypes.NewTestMetadata(),
								Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
								},
								FromPort: misscanTypes.IntTest(-1),
								ToPort:   misscanTypes.IntTest(-1),
							},
						},
					},
					{
						IsDefault: misscanTypes.BoolTest(true),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Protocol: misscanTypes.StringTest("-1"),
								FromPort: misscanTypes.IntTest(0),
								ToPort:   misscanTypes.IntTest(0),
							},
						},
						EgressRules: []ec2.SecurityGroupRule{
							{
								Protocol: misscanTypes.StringTest("-1"),
								FromPort: misscanTypes.IntTest(0),
								ToPort:   misscanTypes.IntTest(0),
								CIDRs:    []misscanTypes.StringValue{misscanTypes.StringTest("0.0.0.0/0")},
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Type:     misscanTypes.String("ingress", misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String("allow", misscanTypes.NewTestMetadata()),
								Protocol: misscanTypes.String("tcp", misscanTypes.NewTestMetadata()),
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.String("10.0.0.0/16", misscanTypes.NewTestMetadata()),
								},
								FromPort: misscanTypes.IntTest(22),
								ToPort:   misscanTypes.IntTest(22),
							},
						},
						IsDefaultRule: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `resource "aws_security_group" "example" {
  ingress {
  }

  egress {
  }
}

resource "aws_network_acl_rule" "example" {
}
`,
			expected: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("Managed by Terraform", misscanTypes.NewTestMetadata()),
						IsDefault:   misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						VPCID:       misscanTypes.String("", misscanTypes.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    misscanTypes.NewTestMetadata(),
								Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
								FromPort:    misscanTypes.IntTest(-1),
								ToPort:      misscanTypes.IntTest(-1),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    misscanTypes.NewTestMetadata(),
								Description: misscanTypes.String("", misscanTypes.NewTestMetadata()),
								FromPort:    misscanTypes.IntTest(-1),
								ToPort:      misscanTypes.IntTest(-1),
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Type:     misscanTypes.String("ingress", misscanTypes.NewTestMetadata()),
								Action:   misscanTypes.String("", misscanTypes.NewTestMetadata()),
								Protocol: misscanTypes.String("", misscanTypes.NewTestMetadata()),
								FromPort: misscanTypes.IntTest(-1),
								ToPort:   misscanTypes.IntTest(-1),
							},
						},
						IsDefaultRule: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "aws_flow_log refer to locals",
			terraform: `locals {
  vpc_id = try(aws_vpc.this.id, "")
}

resource "aws_vpc" "this" {
}

resource "aws_flow_log" "this" {
  vpc_id = local.vpc_id
}
`,
			expected: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						IsDefault:       misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						ID:              misscanTypes.String("", misscanTypes.NewTestMetadata()),
						FlowLogsEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "ingress and egress rules",
			terraform: `resource "aws_security_group" "example" {
  name        = "example"
  description = "example"
}

resource "aws_vpc_security_group_egress_rule" "test" {
  security_group_id = aws_security_group.example.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_vpc_security_group_ingress_rule" "test" {
  security_group_id = aws_security_group.example.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = "22"
  to_port           = "22"
  ip_protocol       = "tcp"
}
`,
			expected: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Description: misscanTypes.StringTest("example"),
						IngressRules: []ec2.SecurityGroupRule{
							{
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.StringTest("0.0.0.0/0"),
								},
								Protocol: misscanTypes.StringTest("tcp"),
								FromPort: misscanTypes.IntTest(22),
								ToPort:   misscanTypes.IntTest(22),
							},
						},
						EgressRules: []ec2.SecurityGroupRule{
							{
								CIDRs: []misscanTypes.StringValue{
									misscanTypes.StringTest("0.0.0.0/0"),
								},
								Protocol: misscanTypes.StringTest("-1"),
								FromPort: misscanTypes.IntTest(-1),
								ToPort:   misscanTypes.IntTest(-1),
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
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestVPCLines(t *testing.T) {
	src := `
resource "aws_default_vpc" "default" {
}

resource "aws_vpc" "main" {
  cidr_block = "4.5.6.7/32"
}

resource "aws_security_group" "example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    cidr_blocks = ["1.2.3.4/32"]
  }
}

resource "aws_security_group_rule" "example" {
  type              = "ingress"
  security_group_id = aws_security_group.example.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks = [
    "1.2.3.4/32",
    "4.5.6.7/32",
  ]
}

resource "aws_network_acl_rule" "example" {
  egress      = false
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  rule_action = "allow"
  cidr_block  = "10.0.0.0/16"
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.VPCs, 2)
	require.Len(t, adapted.SecurityGroups, 1)
	require.Len(t, adapted.NetworkACLs, 1)

	defaultVPC := adapted.VPCs[0]
	securityGroup := adapted.SecurityGroups[0]
	networkACL := adapted.NetworkACLs[0]

	assert.Equal(t, 2, defaultVPC.Metadata.Range().GetStartLine())
	assert.Equal(t, 3, defaultVPC.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 24, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 11, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, securityGroup.Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, securityGroup.IngressRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 19, securityGroup.IngressRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 14, securityGroup.IngressRules[0].Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, securityGroup.IngressRules[0].Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, securityGroup.IngressRules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, securityGroup.IngressRules[0].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, securityGroup.IngressRules[1].Metadata.Range().GetStartLine())
	assert.Equal(t, 36, securityGroup.IngressRules[1].Metadata.Range().GetEndLine())

	assert.Equal(t, 32, securityGroup.IngressRules[1].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, securityGroup.IngressRules[1].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, securityGroup.EgressRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 23, securityGroup.EgressRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 22, securityGroup.EgressRules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, securityGroup.EgressRules[0].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, networkACL.Rules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 45, networkACL.Rules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 39, networkACL.Rules[0].Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 39, networkACL.Rules[0].Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 40, networkACL.Rules[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, networkACL.Rules[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 43, networkACL.Rules[0].Action.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 43, networkACL.Rules[0].Action.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 44, networkACL.Rules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 44, networkACL.Rules[0].CIDRs[0].GetMetadata().Range().GetEndLine())
}
