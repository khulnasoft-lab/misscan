package secrets

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/github"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []github.EnvironmentSecret
	}{
		{
			name: "basic",
			terraform: `
resource "github_actions_environment_secret" "example" {
}
`,
			expected: []github.EnvironmentSecret{
				{
					Metadata:       misscanTypes.NewTestMetadata(),
					Environment:    misscanTypes.String("", misscanTypes.NewTestMetadata()),
					SecretName:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
					PlainTextValue: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					EncryptedValue: misscanTypes.String("", misscanTypes.NewTestMetadata()),
					Repository:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "github_actions_environment_secret" "example" {
    secret_name     = "a"
	plaintext_value = "b"
	environment     = "c"
	encrypted_value = "d"
	repository      = "e"
}
`,
			expected: []github.EnvironmentSecret{
				{
					Metadata:       misscanTypes.NewTestMetadata(),
					SecretName:     misscanTypes.String("a", misscanTypes.NewTestMetadata()),
					PlainTextValue: misscanTypes.String("b", misscanTypes.NewTestMetadata()),
					Environment:    misscanTypes.String("c", misscanTypes.NewTestMetadata()),
					EncryptedValue: misscanTypes.String("d", misscanTypes.NewTestMetadata()),
					Repository:     misscanTypes.String("e", misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
