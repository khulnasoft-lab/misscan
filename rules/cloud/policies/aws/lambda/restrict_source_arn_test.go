package lambda

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/lambda"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRestrictSourceArn(t *testing.T) {
	tests := []struct {
		name     string
		input    lambda.Lambda
		expected bool
	}{
		{
			name: "Lambda function permission missing source ARN",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								Principal: misscanTypes.String("sns.amazonaws.com", misscanTypes.NewTestMetadata()),
								SourceARN: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Lambda function permission with source ARN",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								Principal: misscanTypes.String("sns.amazonaws.com", misscanTypes.NewTestMetadata()),
								SourceARN: misscanTypes.String("source-arn", misscanTypes.NewTestMetadata()),
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
			testState.AWS.Lambda = test.input
			results := CheckRestrictSourceArn.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRestrictSourceArn.Rule().LongID() {
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
