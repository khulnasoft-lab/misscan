package eks

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableControlPlaneLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS cluster with all cluster logging disabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Audit:             misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Authenticator:     misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							ControllerManager: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Scheduler:         misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with only some cluster logging enabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							Audit:             misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Authenticator:     misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
							ControllerManager: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Scheduler:         misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with all cluster logging enabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Audit:             misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Authenticator:     misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							ControllerManager: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							Scheduler:         misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckEnableControlPlaneLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableControlPlaneLogging.Rule().LongID() {
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
