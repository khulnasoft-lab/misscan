package config

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/config"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getConfigurationAggregator(ctx parser.FileContext) config.ConfigurationAggregrator {

	aggregator := config.ConfigurationAggregrator{
		Metadata:         misscanTypes.NewUnmanagedMetadata(),
		SourceAllRegions: misscanTypes.BoolDefault(false, ctx.Metadata()),
	}

	aggregatorResources := ctx.GetResourcesByType("AWS::Config::ConfigurationAggregator")

	if len(aggregatorResources) == 0 {
		return aggregator
	}

	return config.ConfigurationAggregrator{
		Metadata:         aggregatorResources[0].Metadata(),
		SourceAllRegions: isSourcingAllRegions(aggregatorResources[0]),
	}
}

func isSourcingAllRegions(r *parser.Resource) misscanTypes.BoolValue {
	accountProp := r.GetProperty("AccountAggregationSources")
	orgProp := r.GetProperty("OrganizationAggregationSource")

	if accountProp.IsNotNil() && accountProp.IsList() {
		for _, a := range accountProp.AsList() {
			regionsProp := a.GetProperty("AllAwsRegions")
			if regionsProp.IsNil() || regionsProp.IsBool() {
				return regionsProp.AsBoolValue()
			}
		}
	}

	if orgProp.IsNotNil() {
		regionsProp := orgProp.GetProperty("AllAwsRegions")
		if regionsProp.IsBool() {
			return regionsProp.AsBoolValue()
		}
	}

	// nothing is set or resolvable so its got to be false
	return misscanTypes.BoolDefault(false, r.Metadata())
}
