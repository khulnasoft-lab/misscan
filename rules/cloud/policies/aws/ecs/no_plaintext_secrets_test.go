package ecs

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecs"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlaintextSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Task definition with plaintext sensitive information",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								Name:      misscanTypes.String("my_service", misscanTypes.NewTestMetadata()),
								Image:     misscanTypes.String("my_image", misscanTypes.NewTestMetadata()),
								CPU:       misscanTypes.Int(2, misscanTypes.NewTestMetadata()),
								Memory:    misscanTypes.Int(256, misscanTypes.NewTestMetadata()),
								Essential: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
									},
									{
										Name:  "DATABASE_PASSWORD",
										Value: "password123",
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Task definition without sensitive information",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								Name:      misscanTypes.String("my_service", misscanTypes.NewTestMetadata()),
								Image:     misscanTypes.String("my_image", misscanTypes.NewTestMetadata()),
								CPU:       misscanTypes.Int(2, misscanTypes.NewTestMetadata()),
								Memory:    misscanTypes.Int(256, misscanTypes.NewTestMetadata()),
								Essential: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
									},
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
			testState.AWS.ECS = test.input
			results := CheckNoPlaintextSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPlaintextSecrets.Rule().LongID() {
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
