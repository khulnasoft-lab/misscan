package athena

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/athena"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    athena.Athena
		expected bool
	}{
		{
			name: "AWS Athena database unencrypted",
			input: athena.Athena{
				Databases: []athena.Database{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String(athena.EncryptionTypeNone, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Athena workgroup unencrypted",
			input: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String(athena.EncryptionTypeNone, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Athena database and workgroup encrypted",
			input: athena.Athena{
				Databases: []athena.Database{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String(athena.EncryptionTypeSSEKMS, misscanTypes.NewTestMetadata()),
						},
					},
				},
				Workgroups: []athena.Workgroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: misscanTypes.NewTestMetadata(),
							Type:     misscanTypes.String(athena.EncryptionTypeSSEKMS, misscanTypes.NewTestMetadata()),
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
			testState.AWS.Athena = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.Rule().LongID() {
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
