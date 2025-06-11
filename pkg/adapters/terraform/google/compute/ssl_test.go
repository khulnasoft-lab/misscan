package compute

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptSSLPolicies(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.SSLPolicy
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_ssl_policy" "example" {
				name    = "production-ssl-policy"
				profile = "MODERN"
				min_tls_version = "TLS_1_2"
			  }
`,
			expected: []compute.SSLPolicy{
				{
					Metadata:          misscanTypes.NewTestMetadata(),
					Name:              misscanTypes.String("production-ssl-policy", misscanTypes.NewTestMetadata()),
					Profile:           misscanTypes.String("MODERN", misscanTypes.NewTestMetadata()),
					MinimumTLSVersion: misscanTypes.String("TLS_1_2", misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_ssl_policy" "example" {
			  }
`,
			expected: []compute.SSLPolicy{
				{
					Metadata:          misscanTypes.NewTestMetadata(),
					Name:              misscanTypes.String("", misscanTypes.NewTestMetadata()),
					Profile:           misscanTypes.String("", misscanTypes.NewTestMetadata()),
					MinimumTLSVersion: misscanTypes.String("TLS_1_0", misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSSLPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
