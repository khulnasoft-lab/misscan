package spaces

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean/spaces"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptBuckets(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []spaces.Bucket
	}{
		{
			name: "basic",
			terraform: `
			resource "digitalocean_spaces_bucket" "example" {
				name   = "public_space"
				region = "nyc3"
				acl    = "private"

				force_destroy = true

				versioning {
					enabled = true
				  }
			  }
			  
			  resource "digitalocean_spaces_bucket_object" "index" {
				bucket       = digitalocean_spaces_bucket.example.name
				acl          = "private"
			  }
`,
			expected: []spaces.Bucket{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("public_space", misscanTypes.NewTestMetadata()),
					Objects: []spaces.Object{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							ACL:      misscanTypes.String("private", misscanTypes.NewTestMetadata()),
						},
					},
					ACL:          misscanTypes.String("private", misscanTypes.NewTestMetadata()),
					ForceDestroy: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					Versioning: spaces.Versioning{
						Metadata: misscanTypes.NewTestMetadata(),
						Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "digitalocean_spaces_bucket" "example" {
			  }
			
`,
			expected: []spaces.Bucket{
				{
					Metadata:     misscanTypes.NewTestMetadata(),
					Name:         misscanTypes.String("", misscanTypes.NewTestMetadata()),
					Objects:      nil,
					ACL:          misscanTypes.String("private", misscanTypes.NewTestMetadata()),
					ForceDestroy: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					Versioning: spaces.Versioning{
						Metadata: misscanTypes.NewTestMetadata(),
						Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptBuckets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "digitalocean_spaces_bucket" "example" {
		name   = "public_space"
		region = "nyc3"
		acl    = "private"

		force_destroy = true

		versioning {
			enabled = true
		  }
	  }
	  
	  resource "digitalocean_spaces_bucket_object" "index" {
		bucket       = digitalocean_spaces_bucket.example.name
		acl          = "public-read"
	  }
	`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Buckets, 1)
	bucket := adapted.Buckets[0]

	assert.Equal(t, 2, bucket.Metadata.Range().GetStartLine())
	assert.Equal(t, 12, bucket.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, bucket.ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, bucket.ACL.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, bucket.ForceDestroy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, bucket.ForceDestroy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, bucket.Versioning.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, bucket.Versioning.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, bucket.Versioning.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, bucket.Versioning.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, bucket.Objects[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 17, bucket.Objects[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 16, bucket.Objects[0].ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, bucket.Objects[0].ACL.GetMetadata().Range().GetEndLine())

}
