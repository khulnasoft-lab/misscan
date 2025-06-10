package gke

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckMetadataEndpointsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster legacy metadata endpoints enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              misscanTypes.NewTestMetadata(),
							EnableLegacyEndpoints: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster legacy metadata endpoints disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              misscanTypes.NewTestMetadata(),
							EnableLegacyEndpoints: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints disabled on non-default node pool",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              misscanTypes.NewTestMetadata(),
							EnableLegacyEndpoints: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints enabled on non-default node pool",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              misscanTypes.NewTestMetadata(),
							EnableLegacyEndpoints: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.GKE = test.input
			results := CheckMetadataEndpointsDisabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckMetadataEndpointsDisabled.Rule().LongID() {
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
