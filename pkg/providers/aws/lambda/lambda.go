package lambda

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	Metadata    misscanTypes.Metadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	Metadata misscanTypes.Metadata
	Mode     misscanTypes.StringValue
}

type Permission struct {
	Metadata  misscanTypes.Metadata
	Principal misscanTypes.StringValue
	SourceARN misscanTypes.StringValue
}
