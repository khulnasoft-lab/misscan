package config

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/config"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) config.Config {
	return config.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
	}
}

func adaptConfigurationAggregrator(modules terraform.Modules) config.ConfigurationAggregrator {
	configurationAggregrator := config.ConfigurationAggregrator{
		Metadata:         misscanTypes.NewUnmanagedMetadata(),
		SourceAllRegions: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_config_configuration_aggregator") {
		configurationAggregrator.Metadata = resource.GetMetadata()
		aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
		if aggregationBlock.IsNil() {
			configurationAggregrator.SourceAllRegions = misscanTypes.Bool(false, resource.GetMetadata())
		} else {
			allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
			allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
			configurationAggregrator.SourceAllRegions = allRegionsVal
		}
	}
	return configurationAggregrator
}
