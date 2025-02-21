package sam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Function struct {
	Metadata        misscanTypes.Metadata
	FunctionName    misscanTypes.StringValue
	Tracing         misscanTypes.StringValue
	ManagedPolicies []misscanTypes.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	Metadata  misscanTypes.Metadata
	Principal misscanTypes.StringValue
	SourceARN misscanTypes.StringValue
}
