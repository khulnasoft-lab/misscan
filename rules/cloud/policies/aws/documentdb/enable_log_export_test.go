package documentdb

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogExport(t *testing.T) {
	tests := []struct {
		name     string
		input    documentdb.DocumentDB
		expected bool
	}{
		{
			name: "DocDB Cluster not exporting logs",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EnabledLogExports: []misscanTypes.StringValue{
							misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB Cluster exporting audit logs",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EnabledLogExports: []misscanTypes.StringValue{
							misscanTypes.String(documentdb.LogExportAudit, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "DocDB Cluster exporting profiler logs",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EnabledLogExports: []misscanTypes.StringValue{
							misscanTypes.String(documentdb.LogExportProfiler, misscanTypes.NewTestMetadata()),
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
			testState.AWS.DocumentDB = test.input
			results := CheckEnableLogExport.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogExport.Rule().LongID() {
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
