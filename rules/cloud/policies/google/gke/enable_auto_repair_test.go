package gke

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAutoRepair(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Node pool auto repair disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         misscanTypes.NewTestMetadata(),
									EnableAutoRepair: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Node pool auto repair enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         misscanTypes.NewTestMetadata(),
									EnableAutoRepair: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								},
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
			results := CheckEnableAutoRepair.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAutoRepair.Rule().LongID() {
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
