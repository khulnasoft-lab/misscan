package nas

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateNASInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    nas.NAS
		expected bool
	}{
		{
			name: "NIFCLOUD nas instance with common private",
			input: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						NetworkID: misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD nas instance with private LAN",
			input: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						NetworkID: misscanTypes.String("net-some-private-lan", misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.NAS = test.input
			results := CheckNoCommonPrivateNASInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateNASInstance.Rule().LongID() {
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
