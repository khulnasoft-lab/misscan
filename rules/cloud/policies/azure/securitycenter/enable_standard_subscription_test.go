package securitycenter

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/securitycenter"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStandardSubscription(t *testing.T) {
	tests := []struct {
		name     string
		input    securitycenter.SecurityCenter
		expected bool
	}{
		{
			name: "Security center set with free subscription",
			input: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Tier:     misscanTypes.String(securitycenter.TierFree, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Security center set with standard subscription",
			input: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Tier:     misscanTypes.String(securitycenter.TierStandard, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.SecurityCenter = test.input
			results := CheckEnableStandardSubscription.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStandardSubscription.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
