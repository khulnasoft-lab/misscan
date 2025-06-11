package kinesis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kinesis"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptStream(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  kinesis.Stream
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kinesis_stream" "example" {
				encryption_type = "KMS"
				kms_key_id = "my/special/key"
			}
`,
			expected: kinesis.Stream{
				Metadata: misscanTypes.NewTestMetadata(),
				Encryption: kinesis.Encryption{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String("KMS", misscanTypes.NewTestMetadata()),
					KMSKeyID: misscanTypes.String("my/special/key", misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_kinesis_stream" "example" {
			}
`,
			expected: kinesis.Stream{
				Metadata: misscanTypes.NewTestMetadata(),
				Encryption: kinesis.Encryption{
					Metadata: misscanTypes.NewTestMetadata(),
					Type:     misscanTypes.String("NONE", misscanTypes.NewTestMetadata()),
					KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptStream(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kinesis_stream" "example" {
		encryption_type = "KMS"
		kms_key_id = "my/special/key"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Streams, 1)
	stream := adapted.Streams[0]

	assert.Equal(t, 2, stream.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, stream.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, stream.Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, stream.Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, stream.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, stream.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
