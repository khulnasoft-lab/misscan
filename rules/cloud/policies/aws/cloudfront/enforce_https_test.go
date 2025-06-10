package cloudfront

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudfront"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution default cache behaviour with allow all policy",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             misscanTypes.NewTestMetadata(),
							ViewerProtocolPolicy: misscanTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution ordered cache behaviour with allow all policy",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             misscanTypes.NewTestMetadata(),
							ViewerProtocolPolicy: misscanTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, misscanTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             misscanTypes.NewTestMetadata(),
								ViewerProtocolPolicy: misscanTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution cache behaviours allowing HTTPS only",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             misscanTypes.NewTestMetadata(),
							ViewerProtocolPolicy: misscanTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, misscanTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             misscanTypes.NewTestMetadata(),
								ViewerProtocolPolicy: misscanTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, misscanTypes.NewTestMetadata()),
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
			testState.AWS.Cloudfront = test.input
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.Rule().LongID() {
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
