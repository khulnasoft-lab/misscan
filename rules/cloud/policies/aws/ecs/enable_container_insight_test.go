package ecs

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecs"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableContainerInsight(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Cluster with disabled container insights",
			input: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 misscanTypes.NewTestMetadata(),
							ContainerInsightsEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with enabled container insights",
			input: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 misscanTypes.NewTestMetadata(),
							ContainerInsightsEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.ECS = test.input
			results := CheckEnableContainerInsight.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableContainerInsight.Rule().LongID() {
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
