package sam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckApiUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "SAM API TLS v1.0",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       misscanTypes.NewTestMetadata(),
							SecurityPolicy: misscanTypes.String("TLS_1_0", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SAM API TLS v1.2",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       misscanTypes.NewTestMetadata(),
							SecurityPolicy: misscanTypes.String("TLS_1_2", misscanTypes.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckApiUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckApiUseSecureTlsPolicy.Rule().LongID() {
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
