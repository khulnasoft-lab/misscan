package ssm

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ssm"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ssm.SSM
	}{
		{
			name: "reference key",
			terraform: `
			resource "aws_kms_key" "secrets" {
				enable_key_rotation = true
			}
			
			resource "aws_secretsmanager_secret" "example" {
			  name       = "lambda_password"
			  kms_key_id = aws_kms_key.secrets.arn
			}
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("aws_kms_key.secrets", misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "string key",
			terraform: `
			resource "aws_secretsmanager_secret" "example" {
			  name       = "lambda_password"
			  kms_key_id = "key_id"
			}
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("key_id", misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_secretsmanager_secret" "example" {
			}
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						KMSKeyID: misscanTypes.String("alias/aws/secretsmanager", misscanTypes.NewTestMetadata()),
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
	resource "aws_kms_key" "secrets" {
		enable_key_rotation = true
	}
	
	resource "aws_secretsmanager_secret" "example" {
	  name       = "lambda_password"
	  kms_key_id = aws_kms_key.secrets.arn
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Secrets, 1)
	secret := adapted.Secrets[0]

	assert.Equal(t, 6, secret.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, secret.Metadata.Range().GetEndLine())

	assert.Equal(t, 2, secret.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, secret.KMSKeyID.GetMetadata().Range().GetEndLine())

}
