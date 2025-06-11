package compute

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptDisks(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Disk
	}{
		{
			name: "key as string link or raw bytes",
			terraform: `
			resource "google_compute_disk" "example-one" {
				name  = "disk #1"
			
				disk_encryption_key {
				  kms_key_self_link = "something"
				}
			  }

			  resource "google_compute_disk" "example-two" {
				name  = "disk #2"
			
				disk_encryption_key {
				  raw_key="b2ggbm8gdGhpcyBpcyBiYWQ"
				}
			  }
`,
			expected: []compute.Disk{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("disk #1", misscanTypes.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   misscanTypes.NewTestMetadata(),
						KMSKeyLink: misscanTypes.String("something", misscanTypes.NewTestMetadata()),
					},
				},
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("disk #2", misscanTypes.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   misscanTypes.NewTestMetadata(),
						KMSKeyLink: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						RawKey:     misscanTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "key link as reference",
			terraform: `
			resource "google_kms_crypto_key" "my_crypto_key" {
				name            = "crypto-key-example"
			  }

			resource "google_compute_disk" "example-three" {
				name  = "disk #3"
			
				disk_encryption_key {
					kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
				}
			  }`,
			expected: []compute.Disk{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("disk #3", misscanTypes.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   misscanTypes.NewTestMetadata(),
						KMSKeyLink: misscanTypes.String("google_kms_crypto_key.my_crypto_key", misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDisks(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
