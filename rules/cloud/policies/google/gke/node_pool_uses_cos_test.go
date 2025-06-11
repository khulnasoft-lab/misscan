package gke

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNodePoolUsesCos(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node config image type set to Ubuntu",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  misscanTypes.NewTestMetadata(),
							ImageType: misscanTypes.String("UBUNTU", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node pool image type set to Ubuntu",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  misscanTypes.NewTestMetadata(),
							ImageType: misscanTypes.String("COS", misscanTypes.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata:  misscanTypes.NewTestMetadata(),
									ImageType: misscanTypes.String("UBUNTU", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node config image type set to Container-Optimized OS",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  misscanTypes.NewTestMetadata(),
							ImageType: misscanTypes.String("COS_CONTAINERD", misscanTypes.NewTestMetadata()),
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
			testState.Google.GKE = test.input
			results := CheckNodePoolUsesCos.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNodePoolUsesCos.Rule().LongID() {
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
