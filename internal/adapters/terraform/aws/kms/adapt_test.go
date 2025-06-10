package kms

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kms"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"

	"github.com/khulnasoft-lab/misscan/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptKey(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  kms.Key
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kms_key" "example" {
				enable_key_rotation = true
				key_usage = "SIGN_VERIFY"
			}
`,
			expected: kms.Key{
				Usage:           misscanTypes.String(kms.KeyUsageSignAndVerify, misscanTypes.NewTestMetadata()),
				RotationEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_kms_key" "example" {
			}
`,
			expected: kms.Key{
				Usage:           misscanTypes.String("ENCRYPT_DECRYPT", misscanTypes.NewTestMetadata()),
				RotationEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptKey(modules.GetBlocks()[0])
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "example" {
		enable_key_rotation = true
		key_usage = SIGN_VERIFY
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Keys, 1)
	key := adapted.Keys[0]

	assert.Equal(t, 2, key.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, key.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, key.RotationEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, key.RotationEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, key.Usage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, key.Usage.GetMetadata().Range().GetEndLine())

}
