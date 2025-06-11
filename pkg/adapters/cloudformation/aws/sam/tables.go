package sam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getSimpleTables(cfFile parser.FileContext) (tables []sam.SimpleTable) {

	tableResources := cfFile.GetResourcesByType("AWS::Serverless::SimpleTable")
	for _, r := range tableResources {
		table := sam.SimpleTable{
			Metadata:         r.Metadata(),
			TableName:        r.GetStringProperty("TableName"),
			SSESpecification: getSSESpecification(r),
		}

		tables = append(tables, table)
	}

	return tables
}

func getSSESpecification(r *parser.Resource) sam.SSESpecification {
	if sse := r.GetProperty("SSESpecification"); sse.IsNotNil() {
		return sam.SSESpecification{
			Metadata:       sse.Metadata(),
			Enabled:        sse.GetBoolProperty("SSEEnabled"),
			KMSMasterKeyID: sse.GetStringProperty("KMSMasterKeyId"),
		}
	}

	return sam.SSESpecification{
		Metadata:       r.Metadata(),
		Enabled:        misscanTypes.BoolDefault(false, r.Metadata()),
		KMSMasterKeyID: misscanTypes.StringDefault("", r.Metadata()),
	}
}
