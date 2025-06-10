package appservice

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/appservice"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAccountIdentityRegistered(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "App service identity not registered",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Identity: struct{ Type misscanTypes.StringValue }{
							Type: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service identity registered",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Identity: struct{ Type misscanTypes.StringValue }{
							Type: misscanTypes.String("UserAssigned", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.AppService = test.input
			results := CheckAccountIdentityRegistered.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAccountIdentityRegistered.Rule().LongID() {
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
