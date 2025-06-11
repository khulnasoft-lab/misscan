package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckIMDSAccessRequiresToken(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Launch configuration with optional tokens",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     misscanTypes.NewTestMetadata(),
							HttpTokens:   misscanTypes.String("optional", misscanTypes.NewTestMetadata()),
							HttpEndpoint: misscanTypes.String("enabled", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch template with optional tokens",
			input: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: misscanTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								Metadata:     misscanTypes.NewTestMetadata(),
								HttpTokens:   misscanTypes.String("optional", misscanTypes.NewTestMetadata()),
								HttpEndpoint: misscanTypes.String("enabled", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration with required tokens",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     misscanTypes.NewTestMetadata(),
							HttpTokens:   misscanTypes.String("required", misscanTypes.NewTestMetadata()),
							HttpEndpoint: misscanTypes.String("enabled", misscanTypes.NewTestMetadata()),
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
			testState.AWS.EC2 = test.input
			results := CheckASIMDSAccessRequiresToken.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckASIMDSAccessRequiresToken.Rule().LongID() {
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
