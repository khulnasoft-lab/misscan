package datafactory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/datafactory"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptFactory(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  datafactory.Factory
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_data_factory" "example" {
				name                = "example"
				location            = azurerm_resource_group.example.location
				resource_group_name = azurerm_resource_group.example.name
				public_network_enabled = false
			  }
`,
			expected: datafactory.Factory{
				Metadata:            misscanTypes.NewTestMetadata(),
				EnablePublicNetwork: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "default",
			terraform: `
			resource "azurerm_data_factory" "example" {
				name                = "example"
			  }
`,
			expected: datafactory.Factory{
				Metadata:            misscanTypes.NewTestMetadata(),
				EnablePublicNetwork: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptFactory(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_data_factory" "example" {
		name                = "example"
		location            = azurerm_resource_group.example.location
		resource_group_name = azurerm_resource_group.example.name
		public_network_enabled = false
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.DataFactories, 1)
	dataFactory := adapted.DataFactories[0]

	assert.Equal(t, 6, dataFactory.EnablePublicNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, dataFactory.EnablePublicNetwork.GetMetadata().Range().GetEndLine())

}
