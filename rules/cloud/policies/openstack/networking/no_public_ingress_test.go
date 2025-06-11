package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/openstack"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Networking
		expected bool
	}{
		{
			name: "Security group rule missing address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								IsIngress: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CIDR:      misscanTypes.String("", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								IsIngress: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CIDR:      misscanTypes.String("10.10.0.1", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								IsIngress: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CIDR:      misscanTypes.String("8.8.8.8", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								IsIngress: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
								CIDR:      misscanTypes.String("80.0.0.0/8", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Networking = test.input
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.Rule().LongID() {
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
