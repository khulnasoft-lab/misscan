package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/kms"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptKeyRings(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []kms.KeyRing
	}{
		{
			name: "configured",
			terraform: `
			resource "google_kms_key_ring" "keyring" {
				name     = "keyring-example"
			  }
			  
			  resource "google_kms_crypto_key" "example-key" {
				name            = "crypto-key-example"
				key_ring        = google_kms_key_ring.keyring.id
				rotation_period = "7776000s"
			  }
`,
			expected: []kms.KeyRing{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Keys: []kms.Key{
						{
							Metadata:              misscanTypes.NewTestMetadata(),
							RotationPeriodSeconds: misscanTypes.Int(7776000, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "no keys",
			terraform: `
			resource "google_kms_key_ring" "keyring" {
				name     = "keyring-example"
			  }

`,
			expected: []kms.KeyRing{
				{
					Metadata: misscanTypes.NewTestMetadata(),
				},
			},
		},
		{
			name: "default rotation period",
			terraform: `
			resource "google_kms_key_ring" "keyring" {
				name     = "keyring-example"
			  }
			  
			  resource "google_kms_crypto_key" "example-key" {
				name            = "crypto-key-example"
				key_ring        = google_kms_key_ring.keyring.id
			  }
`,
			expected: []kms.KeyRing{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Keys: []kms.Key{
						{
							Metadata:              misscanTypes.NewTestMetadata(),
							RotationPeriodSeconds: misscanTypes.Int(-1, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptKeyRings(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "google_kms_key_ring" "keyring" {
		name     = "keyring-example"
	  }
	  
	  resource "google_kms_crypto_key" "example-key" {
		name            = "crypto-key-example"
		key_ring        = google_kms_key_ring.keyring.id
		rotation_period = "7776000s"
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.KeyRings, 1)
	require.Len(t, adapted.KeyRings[0].Keys, 1)

	key := adapted.KeyRings[0].Keys[0]

	assert.Equal(t, 2, adapted.KeyRings[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 4, adapted.KeyRings[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 6, key.Metadata.Range().GetStartLine())
	assert.Equal(t, 10, key.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, key.RotationPeriodSeconds.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, key.RotationPeriodSeconds.GetMetadata().Range().GetEndLine())

}
