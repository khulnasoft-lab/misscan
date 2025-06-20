package athena

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/athena"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptDatabase(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  athena.Database
	}{
		{
			name: "athena database",
			terraform: `
			resource "aws_athena_database" "my_wg" {
				name   = "database_name"
			  
				encryption_configuration {
				   encryption_option = "SSE_KMS"
			   }
			}
`,
			expected: athena.Database{
				Metadata: misscanTypes.NewTestMetadata(),
				Name:     misscanTypes.String("database_name", misscanTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String(athena.EncryptionTypeSSEKMS, misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDatabase(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWorkgroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  athena.Workgroup
	}{
		{
			name: "encryption type SSE KMS",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
				  enforce_workgroup_configuration    = true
			  
				  result_configuration {
					encryption_configuration {
					  encryption_option = "SSE_KMS"
					}
				  }
				}
			  }
`,
			expected: athena.Workgroup{
				Metadata: misscanTypes.NewTestMetadata(),
				Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String(athena.EncryptionTypeSSEKMS, misscanTypes.NewTestMetadata()),
				},
				EnforceConfiguration: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "configuration not enforced",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
				  enforce_workgroup_configuration    = false
			  
				  result_configuration {
					encryption_configuration {
					  encryption_option = "SSE_KMS"
					}
				  }
				}
			}
`,
			expected: athena.Workgroup{
				Metadata: misscanTypes.NewTestMetadata(),
				Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String(athena.EncryptionTypeSSEKMS, misscanTypes.NewTestMetadata()),
				},
				EnforceConfiguration: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "enforce configuration defaults to true",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
					result_configuration {
						encryption_configuration {
						  encryption_option = ""
						}
					}
				}
			}
`,
			expected: athena.Workgroup{
				Metadata: misscanTypes.NewTestMetadata(),
				Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String(athena.EncryptionTypeNone, misscanTypes.NewTestMetadata()),
				},
				EnforceConfiguration: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "missing configuration block",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			}
`,
			expected: athena.Workgroup{
				Metadata: misscanTypes.NewTestMetadata(),
				Name:     misscanTypes.String("example", misscanTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String(athena.EncryptionTypeNone, misscanTypes.NewTestMetadata()),
				},
				EnforceConfiguration: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWorkgroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_athena_database" "good_example" {
		name   = "database_name"
		bucket = aws_s3_bucket.hoge.bucket
	  
		encryption_configuration {
		   encryption_option = "SSE_KMS"
		   kms_key_arn       = aws_kms_key.example.arn
	   }
	  }
	  
	  resource "aws_athena_workgroup" "good_example" {
		name = "example"
	  
		configuration {
		  enforce_workgroup_configuration    = true
		  publish_cloudwatch_metrics_enabled = true
	  
		  result_configuration {
			output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
	  
			encryption_configuration {
			  encryption_option = "SSE_KMS"
			  kms_key_arn       = aws_kms_key.example.arn
			}
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Databases, 1)
	require.Len(t, adapted.Workgroups, 1)

	assert.Equal(t, 7, adapted.Databases[0].Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, adapted.Databases[0].Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, adapted.Workgroups[0].EnforceConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, adapted.Workgroups[0].EnforceConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, adapted.Workgroups[0].Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, adapted.Workgroups[0].Encryption.Type.GetMetadata().Range().GetEndLine())
}
