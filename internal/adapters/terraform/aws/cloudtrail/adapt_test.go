package cloudtrail

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptTrail(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cloudtrail.Trail
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_cloudtrail" "example" {
				name = "example"
				is_multi_region_trail = true
			  
				enable_log_file_validation = true
				kms_key_id = "kms-key"
				s3_bucket_name = "abcdefgh"
				cloud_watch_logs_group_arn = "abc"
				enable_logging = false
			}
`,
			expected: cloudtrail.Trail{
				Metadata:                  misscanTypes.NewTestMetadata(),
				Name:                      misscanTypes.String("example", misscanTypes.NewTestMetadata()),
				EnableLogFileValidation:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				IsMultiRegion:             misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				KMSKeyID:                  misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
				CloudWatchLogsLogGroupArn: misscanTypes.String("abc", misscanTypes.NewTestMetadata()),
				IsLogging:                 misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				BucketName:                misscanTypes.String("abcdefgh", misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_cloudtrail" "example" {
			}
`,
			expected: cloudtrail.Trail{
				Metadata:                  misscanTypes.NewTestMetadata(),
				Name:                      misscanTypes.String("", misscanTypes.NewTestMetadata()),
				EnableLogFileValidation:   misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				IsMultiRegion:             misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				KMSKeyID:                  misscanTypes.String("", misscanTypes.NewTestMetadata()),
				BucketName:                misscanTypes.String("", misscanTypes.NewTestMetadata()),
				CloudWatchLogsLogGroupArn: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				IsLogging:                 misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTrail(modules.GetBlocks()[0])
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudtrail" "example" {
		name = "example"
		is_multi_region_trail = true
	  
		enable_log_file_validation = true
		kms_key_id = "kms-key"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Trails, 1)
	trail := adapted.Trails[0]

	assert.Equal(t, 2, trail.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, trail.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, trail.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, trail.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, trail.IsMultiRegion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, trail.IsMultiRegion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, trail.EnableLogFileValidation.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, trail.EnableLogFileValidation.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, trail.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, trail.KMSKeyID.GetMetadata().Range().GetEndLine())
}
