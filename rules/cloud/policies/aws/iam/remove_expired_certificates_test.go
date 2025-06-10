package iam

import (
	"testing"
	"time"

	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRemoveExpiredCertificates(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name:     "No certs",
			input:    iam.IAM{},
			expected: false,
		},
		{
			name: "Valid cert",
			input: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Expiration: misscanTypes.Time(time.Now().Add(time.Hour), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Expired cert",
			input: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Expiration: misscanTypes.Time(time.Now().Add(-time.Hour), misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRemoveExpiredCertificates.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRemoveExpiredCertificates.Rule().LongID() {
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
