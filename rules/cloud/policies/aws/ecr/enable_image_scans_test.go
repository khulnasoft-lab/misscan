package ecr

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecr"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableImageScans(t *testing.T) {
	tests := []struct {
		name     string
		input    ecr.ECR
		expected bool
	}{
		{
			name: "ECR repository with image scans disabled",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   misscanTypes.NewTestMetadata(),
							ScanOnPush: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository with image scans enabled",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   misscanTypes.NewTestMetadata(),
							ScanOnPush: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.ECR = test.input
			results := CheckEnableImageScans.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableImageScans.Rule().LongID() {
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
