package computing

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/computing"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD instance with common private",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								NetworkID: misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with private LAN",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								NetworkID: misscanTypes.String("net-some-private-lan", misscanTypes.NewTestMetadata()),
							},
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
			testState.Nifcloud.Computing = test.input
			results := CheckNoCommonPrivateInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateInstance.Rule().LongID() {
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
