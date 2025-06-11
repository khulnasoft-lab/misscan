package sam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type StateMachine struct {
	Metadata             misscanTypes.Metadata
	Name                 misscanTypes.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []misscanTypes.StringValue
	Policies             []iam.Policy
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	Metadata       misscanTypes.Metadata
	LoggingEnabled misscanTypes.BoolValue
}

type TracingConfiguration struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}
