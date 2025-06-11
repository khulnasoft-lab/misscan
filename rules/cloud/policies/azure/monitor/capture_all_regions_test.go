package monitor

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/monitor"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckCaptureAllRegions(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log profile captures only eastern US region",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Locations: []misscanTypes.StringValue{
							misscanTypes.String("eastus", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures all regions",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Locations: []misscanTypes.StringValue{
							misscanTypes.String("eastus", misscanTypes.NewTestMetadata()),
							misscanTypes.String("eastus2", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southcentralus", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westus2", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westus3", misscanTypes.NewTestMetadata()),
							misscanTypes.String("australiaeast", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southeastasia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("northeurope", misscanTypes.NewTestMetadata()),
							misscanTypes.String("swedencentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("uksouth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westeurope", misscanTypes.NewTestMetadata()),
							misscanTypes.String("centralus", misscanTypes.NewTestMetadata()),
							misscanTypes.String("northcentralus", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westus", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southafricanorth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("centralindia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("eastasia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("japaneast", misscanTypes.NewTestMetadata()),
							misscanTypes.String("jioindiawest", misscanTypes.NewTestMetadata()),
							misscanTypes.String("koreacentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("canadacentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("francecentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("germanywestcentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("norwayeast", misscanTypes.NewTestMetadata()),
							misscanTypes.String("switzerlandnorth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("uaenorth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("brazilsouth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("centralusstage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("eastusstage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("eastus2stage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("northcentralusstage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southcentralusstage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westusstage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westus2stage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("asia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("asiapacific", misscanTypes.NewTestMetadata()),
							misscanTypes.String("australia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("brazil", misscanTypes.NewTestMetadata()),
							misscanTypes.String("canada", misscanTypes.NewTestMetadata()),
							misscanTypes.String("europe", misscanTypes.NewTestMetadata()),
							misscanTypes.String("global", misscanTypes.NewTestMetadata()),
							misscanTypes.String("india", misscanTypes.NewTestMetadata()),
							misscanTypes.String("japan", misscanTypes.NewTestMetadata()),
							misscanTypes.String("uk", misscanTypes.NewTestMetadata()),
							misscanTypes.String("unitedstates", misscanTypes.NewTestMetadata()),
							misscanTypes.String("eastasiastage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southeastasiastage", misscanTypes.NewTestMetadata()),
							misscanTypes.String("centraluseuap", misscanTypes.NewTestMetadata()),
							misscanTypes.String("eastus2euap", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westcentralus", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southafricawest", misscanTypes.NewTestMetadata()),
							misscanTypes.String("australiacentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("australiacentral2", misscanTypes.NewTestMetadata()),
							misscanTypes.String("australiasoutheast", misscanTypes.NewTestMetadata()),
							misscanTypes.String("japanwest", misscanTypes.NewTestMetadata()),
							misscanTypes.String("jioindiacentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("koreasouth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("southindia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("westindia", misscanTypes.NewTestMetadata()),
							misscanTypes.String("canadaeast", misscanTypes.NewTestMetadata()),
							misscanTypes.String("francesouth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("germanynorth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("norwaywest", misscanTypes.NewTestMetadata()),
							misscanTypes.String("swedensouth", misscanTypes.NewTestMetadata()),
							misscanTypes.String("switzerlandwest", misscanTypes.NewTestMetadata()),
							misscanTypes.String("ukwest", misscanTypes.NewTestMetadata()),
							misscanTypes.String("uaecentral", misscanTypes.NewTestMetadata()),
							misscanTypes.String("brazilsoutheast", misscanTypes.NewTestMetadata()),
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
			testState.Azure.Monitor = test.input
			results := CheckCaptureAllRegions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckCaptureAllRegions.Rule().LongID() {
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
