package sam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type API struct {
	Metadata            misscanTypes.Metadata
	Name                misscanTypes.StringValue
	TracingEnabled      misscanTypes.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	Metadata       misscanTypes.Metadata
	ApiKeyRequired misscanTypes.BoolValue
}

type AccessLogging struct {
	Metadata              misscanTypes.Metadata
	CloudwatchLogGroupARN misscanTypes.StringValue
}

type DomainConfiguration struct {
	Metadata       misscanTypes.Metadata
	Name           misscanTypes.StringValue
	SecurityPolicy misscanTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           misscanTypes.Metadata
	CacheDataEncrypted misscanTypes.BoolValue
	LoggingEnabled     misscanTypes.BoolValue
	DataTraceEnabled   misscanTypes.BoolValue
	MetricsEnabled     misscanTypes.BoolValue
}
