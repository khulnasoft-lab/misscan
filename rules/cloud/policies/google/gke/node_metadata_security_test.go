package gke

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNodeMetadataSecurity(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node pools metadata exposed by default",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: misscanTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     misscanTypes.NewTestMetadata(),
								NodeMetadata: misscanTypes.String("UNSPECIFIED", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Node pool metadata exposed",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: misscanTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     misscanTypes.NewTestMetadata(),
								NodeMetadata: misscanTypes.String("SECURE", misscanTypes.NewTestMetadata()),
							},
						},
						NodePools: []gke.NodePool{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata: misscanTypes.NewTestMetadata(),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     misscanTypes.NewTestMetadata(),
										NodeMetadata: misscanTypes.String("EXPOSE", misscanTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node pools metadata secured",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: misscanTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     misscanTypes.NewTestMetadata(),
								NodeMetadata: misscanTypes.String("SECURE", misscanTypes.NewTestMetadata()),
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
			testState.Google.GKE = test.input
			results := CheckNodeMetadataSecurity.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNodeMetadataSecurity.Rule().LongID() {
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
