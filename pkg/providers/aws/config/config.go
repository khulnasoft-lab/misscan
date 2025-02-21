package config

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	Metadata         misscanTypes.Metadata
	SourceAllRegions misscanTypes.BoolValue
}
