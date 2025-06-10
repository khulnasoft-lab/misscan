package sns

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sns"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptTopic(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sns.Topic
	}{
		{
			name: "defined",
			terraform: `
			resource "aws_sns_topic" "good_example" {
				kms_master_key_id = "/blah"
			}
`,
			expected: sns.Topic{
				Metadata: misscanTypes.NewTestMetadata(),
				ARN:      misscanTypes.String("", misscanTypes.NewTestMetadata()),
				Encryption: sns.Encryption{
					Metadata: misscanTypes.NewTestMetadata(),
					KMSKeyID: misscanTypes.String("/blah", misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "default",
			terraform: `
			resource "aws_sns_topic" "good_example" {
			}
`,
			expected: sns.Topic{
				Metadata: misscanTypes.NewTestMetadata(),
				ARN:      misscanTypes.String("", misscanTypes.NewTestMetadata()),
				Encryption: sns.Encryption{
					Metadata: misscanTypes.NewTestMetadata(),
					KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTopic(modules.GetBlocks()[0])
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_sns_topic" "good_example" {
		kms_master_key_id = "/blah"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Topics, 1)
	topic := adapted.Topics[0]

	assert.Equal(t, 2, topic.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, topic.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, topic.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, topic.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
