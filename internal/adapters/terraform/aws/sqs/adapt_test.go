package sqs

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sqs"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/liamg/iamgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sqs.SQS
	}{
		{
			name: "np kms key",
			terraform: `
			resource "aws_sqs_queue" "good_example" {

				policy = <<POLICY
				{
				  "Statement": [
					{
					  "Effect": "Allow",
					  "Action": "*"
					}
				  ]
				}
				POLICY
			}`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						QueueURL: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						Encryption: sqs.Encryption{
							Metadata:          misscanTypes.NewTestMetadata(),
							ManagedEncryption: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID:          misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
						Policies: func() []iam.Policy {
							sb := iamgo.NewStatementBuilder()
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"*",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Metadata: misscanTypes.NewTestMetadata(),
									Name:     misscanTypes.StringDefault("", misscanTypes.NewTestMetadata()),
									Document: iam.Document{
										Metadata: misscanTypes.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
									Builtin: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
							}
						}(),
					},
				},
			},
		},
		{
			name: "no policy",
			terraform: `
			resource "aws_sqs_queue" "good_example" {
				kms_master_key_id = "/blah"
			}`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						QueueURL: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						Encryption: sqs.Encryption{
							Metadata:          misscanTypes.NewTestMetadata(),
							ManagedEncryption: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							KMSKeyID:          misscanTypes.String("/blah", misscanTypes.NewTestMetadata()),
						},
						Policies: nil,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_sqs_queue" "good_example" {
		kms_master_key_id = "key"

		policy = <<POLICY
		{
		  "Statement": [
			{
			  "Effect": "Allow",
			  "Action": "*"
			}
		  ]
		}
		POLICY
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Queues, 1)
	queue := adapted.Queues[0]

	assert.Equal(t, 2, queue.Metadata.Range().GetStartLine())
	assert.Equal(t, 15, queue.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, queue.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, queue.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, queue.Policies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 14, queue.Policies[0].Metadata.Range().GetEndLine())
}
