package gke

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseClusterLabels(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster with no resource labels defined",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       misscanTypes.NewTestMetadata(),
						ResourceLabels: misscanTypes.Map(map[string]string{}, misscanTypes.NewTestMetadata().GetMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with resource labels defined",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ResourceLabels: misscanTypes.Map(map[string]string{
							"env": "staging",
						}, misscanTypes.NewTestMetadata().GetMetadata()),
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
			results := CheckUseClusterLabels.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseClusterLabels.Rule().LongID() {
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
