package neptune

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/neptune"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  neptune.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_neptune_cluster" "example" {
				enable_cloudwatch_logs_exports      = ["audit"]
				storage_encrypted                   = true
				kms_key_arn                         = "kms-key"
			  }
`,
			expected: neptune.Cluster{
				Metadata: misscanTypes.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: misscanTypes.NewTestMetadata(),
					Audit:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				},
				StorageEncrypted: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				KMSKeyID:         misscanTypes.String("kms-key", misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_neptune_cluster" "example" {
			  }
`,
			expected: neptune.Cluster{
				Metadata: misscanTypes.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: misscanTypes.NewTestMetadata(),
					Audit:    misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				},
				StorageEncrypted: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				KMSKeyID:         misscanTypes.String("", misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_neptune_cluster" "example" {
		enable_cloudwatch_logs_exports      = ["audit"]
		storage_encrypted                   = true
		kms_key_arn                         = "kms-key"
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 3, cluster.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.Logging.Audit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.Logging.Audit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.StorageEncrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.StorageEncrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.KMSKeyID.GetMetadata().Range().GetEndLine())
}
