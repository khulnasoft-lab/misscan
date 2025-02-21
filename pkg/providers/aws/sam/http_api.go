package sam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type HttpAPI struct {
	Metadata             misscanTypes.Metadata
	Name                 misscanTypes.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	Metadata               misscanTypes.Metadata
	LoggingEnabled         misscanTypes.BoolValue
	DataTraceEnabled       misscanTypes.BoolValue
	DetailedMetricsEnabled misscanTypes.BoolValue
}
