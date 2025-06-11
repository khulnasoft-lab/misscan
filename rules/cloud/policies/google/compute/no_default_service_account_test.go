package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance service account not specified",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  misscanTypes.NewTestMetadata(),
							Email:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
							IsDefault: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance service account using the default email",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  misscanTypes.NewTestMetadata(),
							Email:     misscanTypes.String("1234567890-compute@developer.gserviceaccount.com", misscanTypes.NewTestMetadata()),
							IsDefault: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance service account with email provided",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  misscanTypes.NewTestMetadata(),
							Email:     misscanTypes.String("proper@email.com", misscanTypes.NewTestMetadata()),
							IsDefault: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckNoDefaultServiceAccount.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoDefaultServiceAccount.Rule().LongID() {
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
