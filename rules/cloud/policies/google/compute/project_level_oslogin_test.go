package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckProjectLevelOslogin(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Compute OS login disabled",
			input: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      misscanTypes.NewTestMetadata(),
					EnableOSLogin: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Compute OS login enabled",
			input: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      misscanTypes.NewTestMetadata(),
					EnableOSLogin: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.Compute = test.input
			results := CheckProjectLevelOslogin.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckProjectLevelOslogin.Rule().LongID() {
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
