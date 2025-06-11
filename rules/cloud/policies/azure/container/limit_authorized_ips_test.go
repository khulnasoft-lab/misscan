package container

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/container"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitAuthorizedIps(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "API server authorized IP ranges undefined",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:                    misscanTypes.NewTestMetadata(),
						EnablePrivateCluster:        misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []misscanTypes.StringValue{},
					},
				},
			},
			expected: true,
		},
		{
			name: "API server authorized IP ranges defined",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:             misscanTypes.NewTestMetadata(),
						EnablePrivateCluster: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []misscanTypes.StringValue{
							misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
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
			results := CheckLimitAuthorizedIps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitAuthorizedIps.Rule().LongID() {
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
