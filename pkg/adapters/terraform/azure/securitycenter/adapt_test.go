package securitycenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/securitycenter"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptContact(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.Contact
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_security_center_contact" "example" {
				phone = "+1-555-555-5555"
				alert_notifications = true
			}
`,
			expected: securitycenter.Contact{
				Metadata:                 misscanTypes.NewTestMetadata(),
				EnableAlertNotifications: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				Phone:                    misscanTypes.String("+1-555-555-5555", misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_security_center_contact" "example" {
			}
`,
			expected: securitycenter.Contact{
				Metadata:                 misscanTypes.NewTestMetadata(),
				EnableAlertNotifications: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				Phone:                    misscanTypes.String("", misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptContact(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSubscription(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.SubscriptionPricing
	}{
		{
			name: "free tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
				tier          = "Free"
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: misscanTypes.NewTestMetadata(),
				Tier:     misscanTypes.String("Free", misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "default - free tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: misscanTypes.NewTestMetadata(),
				Tier:     misscanTypes.String("Free", misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "standard tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
				tier          = "Standard"
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: misscanTypes.NewTestMetadata(),
				Tier:     misscanTypes.String("Standard", misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSubscription(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_security_center_contact" "example" {
		phone = "+1-555-555-5555"
		alert_notifications = true
	}

	resource "azurerm_security_center_subscription_pricing" "example" {
		tier          = "Standard"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Contacts, 1)
	require.Len(t, adapted.Subscriptions, 1)

	contact := adapted.Contacts[0]
	sub := adapted.Subscriptions[0]

	assert.Equal(t, 3, contact.Phone.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, contact.Phone.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, contact.EnableAlertNotifications.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, contact.EnableAlertNotifications.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, sub.Tier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, sub.Tier.GetMetadata().Range().GetEndLine())
}
