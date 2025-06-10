package securitycenter

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/securitycenter"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAlertOnSevereNotifications(t *testing.T) {
	tests := []struct {
		name     string
		input    securitycenter.SecurityCenter
		expected bool
	}{
		{
			name: "Security center alert notifications disabled",
			input: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata:                 misscanTypes.NewTestMetadata(),
						EnableAlertNotifications: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Security center alert notifications enabled",
			input: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata:                 misscanTypes.NewTestMetadata(),
						EnableAlertNotifications: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			results := CheckAlertOnSevereNotifications.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAlertOnSevereNotifications.Rule().LongID() {
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
