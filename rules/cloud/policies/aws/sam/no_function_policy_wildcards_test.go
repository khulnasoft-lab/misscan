package sam

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/iamgo"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoFunctionPolicyWildcards(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "Wildcard action in function policy",
			input: sam.SAM{
				Functions: []sam.Function{
					{
						Metadata: types.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"s3:*",
							})
							sb.WithResources([]string{"arn:aws:s3:::my-bucket/*"})
							sb.WithAWSPrincipals([]string{"*"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: types.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			},
			expected: true,
		},
		{
			name: "Specific action in function policy",
			input: sam.SAM{
				Functions: []sam.Function{
					{
						Metadata: types.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"s3:GetObject",
							})
							sb.WithResources([]string{"arn:aws:s3:::my-bucket/*"})
							sb.WithAWSPrincipals([]string{"proper-value"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: types.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
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
			results := CheckNoFunctionPolicyWildcards.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoFunctionPolicyWildcards.Rule().LongID() {
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
