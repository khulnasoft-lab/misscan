package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/network"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  network.Network
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_network_security_rule" "example" {
				name                        = "example_security_rule"
				network_security_group_name = azurerm_network_security_group.example.name
				direction                   = "Inbound"
				access                      = "Allow"
				protocol                    = "TCP"
				source_port_range           = "*"
				destination_port_ranges     = ["3389"]
				source_address_prefix       = "4.53.160.75"
				destination_address_prefix  = "*"
		   }
		   
		   resource "azurerm_network_security_group" "example" {
			 name                = "tf-appsecuritygroup"
		   }

		   resource "azurerm_network_watcher_flow_log" "example" {
			resource_group_name  = azurerm_resource_group.example.name
			name                 = "example-log"
		  
			retention_policy {
			  enabled = true
			  days    = 7
			}		  
		  }
`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Outbound: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								SourceAddresses: []misscanTypes.StringValue{
									misscanTypes.String("4.53.160.75", misscanTypes.NewTestMetadata()),
								},
								DestinationAddresses: []misscanTypes.StringValue{
									misscanTypes.String("*", misscanTypes.NewTestMetadata()),
								},
								SourcePorts: []network.PortRange{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Start:    misscanTypes.IntTest(0),
										End:      misscanTypes.IntTest(65535),
									},
								},
								DestinationPorts: []network.PortRange{
									{
										Metadata: misscanTypes.NewTestMetadata(),
										Start:    misscanTypes.IntTest(3389),
										End:      misscanTypes.IntTest(3389),
									},
								},
								Protocol: misscanTypes.String("TCP", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Days:     misscanTypes.Int(7, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
		   resource "azurerm_network_security_group" "example" {
			 name                = "tf-appsecuritygroup"
			 security_rule {
			 }
		   }
`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Outbound: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								Allow:    misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Protocol: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							},
						},
					},
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

func Test_adaptWatcherLog(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  network.NetworkWatcherFlowLog
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_network_watcher_flow_log" "watcher" {		
				retention_policy {
					enabled = true
					days = 90
				}
			}
`,
			expected: network.NetworkWatcherFlowLog{
				Metadata: misscanTypes.NewTestMetadata(),
				RetentionPolicy: network.RetentionPolicy{
					Metadata: misscanTypes.NewTestMetadata(),
					Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					Days:     misscanTypes.Int(90, misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_network_watcher_flow_log" "watcher" {
				retention_policy {
				}
			}
`,
			expected: network.NetworkWatcherFlowLog{
				Metadata: misscanTypes.NewTestMetadata(),
				RetentionPolicy: network.RetentionPolicy{
					Metadata: misscanTypes.NewTestMetadata(),
					Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					Days:     misscanTypes.Int(0, misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWatcherLog(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_network_security_group" "example" {
		name                = "tf-appsecuritygroup"
	}
   
	resource "azurerm_network_security_rule" "example" {
		name                        = "example_security_rule"
		network_security_group_name = azurerm_network_security_group.example.name
		direction                   = "Inbound"
		access                      = "Allow"
		protocol                    = "TCP"
		source_port_range           = "*"
		destination_port_ranges     = ["3389"]
		source_address_prefix       = "4.53.160.75"
		destination_address_prefix  = "*"
   }
   
   resource "azurerm_network_watcher_flow_log" "example" {
	resource_group_name  = azurerm_resource_group.example.name
	name                 = "example-log"
  
	retention_policy {
	  enabled = true
	  days    = 7
	}		  
  	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.SecurityGroups, 1)
	require.Len(t, adapted.NetworkWatcherFlowLogs, 1)

	securityGroup := adapted.SecurityGroups[0]
	rule := securityGroup.Rules[0]
	watcher := adapted.NetworkWatcherFlowLogs[0]

	assert.Equal(t, 2, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, rule.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, rule.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, rule.Outbound.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, rule.Outbound.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, rule.Allow.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, rule.Allow.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, rule.Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, rule.Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, rule.SourcePorts[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 12, rule.SourcePorts[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 13, rule.DestinationPorts[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 13, rule.DestinationPorts[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 14, rule.SourceAddresses[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, rule.SourceAddresses[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, rule.DestinationAddresses[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, rule.DestinationAddresses[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, watcher.Metadata.Range().GetStartLine())
	assert.Equal(t, 26, watcher.Metadata.Range().GetEndLine())

	assert.Equal(t, 22, watcher.RetentionPolicy.Metadata.Range().GetStartLine())
	assert.Equal(t, 25, watcher.RetentionPolicy.Metadata.Range().GetEndLine())

	assert.Equal(t, 23, watcher.RetentionPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, watcher.RetentionPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, watcher.RetentionPolicy.Days.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, watcher.RetentionPolicy.Days.GetMetadata().Range().GetEndLine())
}
