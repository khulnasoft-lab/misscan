package container

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/container"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Logging via OMS agent disabled",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: misscanTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Logging via OMS agent enabled",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: misscanTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: misscanTypes.NewTestMetadata(),
								Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.Azure.Container = test.input
			results := CheckLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLogging.Rule().LongID() {
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
