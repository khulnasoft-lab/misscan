package elasticsearch

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elasticsearch"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDomainLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticsearch.Elasticsearch
		expected bool
	}{
		{
			name: "Elasticsearch domain with audit logging disabled",
			input: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						LogPublishing: elasticsearch.LogPublishing{
							Metadata:     misscanTypes.NewTestMetadata(),
							AuditEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elasticsearch domain with audit logging enabled",
			input: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						LogPublishing: elasticsearch.LogPublishing{
							Metadata:     misscanTypes.NewTestMetadata(),
							AuditEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			testState.AWS.Elasticsearch = test.input
			results := CheckEnableDomainLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableDomainLogging.Rule().LongID() {
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
