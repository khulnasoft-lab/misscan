package cloudwatch

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudwatch"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptLogGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []cloudwatch.LogGroup
	}{
		{
			name: "key referencing block",
			terraform: `
			resource "aws_cloudwatch_log_group" "my-group" {
				name = "my-group"
				kms_key_id = aws_kms_key.log_key.arn
			}

			resource "aws_kms_key" "log_key" {
			}
`,
			expected: []cloudwatch.LogGroup{
				{
					Metadata:        misscanTypes.NewTestMetadata(),
					Arn:             misscanTypes.String("", misscanTypes.NewTestMetadata()),
					Name:            misscanTypes.String("my-group", misscanTypes.NewTestMetadata()),
					KMSKeyID:        misscanTypes.String("aws_kms_key.log_key", misscanTypes.NewTestMetadata()),
					RetentionInDays: misscanTypes.Int(0, misscanTypes.NewTestMetadata()),
					MetricFilters:   nil,
				},
			},
		},
		{
			name: "key as string",
			terraform: `
			resource "aws_cloudwatch_log_group" "my-group" {
				name = "my-group"
				kms_key_id = "key-as-string"
			}
`,
			expected: []cloudwatch.LogGroup{
				{
					Metadata:        misscanTypes.NewTestMetadata(),
					Arn:             misscanTypes.String("", misscanTypes.NewTestMetadata()),
					Name:            misscanTypes.String("my-group", misscanTypes.NewTestMetadata()),
					KMSKeyID:        misscanTypes.String("key-as-string", misscanTypes.NewTestMetadata()),
					RetentionInDays: misscanTypes.Int(0, misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "missing key",
			terraform: `
			resource "aws_cloudwatch_log_group" "my-group" {
				name = "my-group"
				retention_in_days = 3
			}
`,
			expected: []cloudwatch.LogGroup{
				{
					Metadata:        misscanTypes.NewTestMetadata(),
					Arn:             misscanTypes.String("", misscanTypes.NewTestMetadata()),
					Name:            misscanTypes.String("my-group", misscanTypes.NewTestMetadata()),
					KMSKeyID:        misscanTypes.String("", misscanTypes.NewTestMetadata()),
					RetentionInDays: misscanTypes.Int(3, misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLogGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudwatch_log_group" "my-group" {
		name = "my-group"
		kms_key_id = aws_kms_key.log_key.arn
		retention_in_days = 3

	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)
	require.Len(t, adapted.LogGroups, 1)
	logGroup := adapted.LogGroups[0]

	assert.Equal(t, 3, logGroup.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, logGroup.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, logGroup.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, logGroup.KMSKeyID.GetMetadata().Range().GetStartLine())

	assert.Equal(t, 5, logGroup.RetentionInDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, logGroup.RetentionInDays.GetMetadata().Range().GetStartLine())
}
