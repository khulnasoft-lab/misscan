package cloudwatch

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudwatch"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) cloudwatch.CloudWatch {
	return cloudwatch.CloudWatch{
		LogGroups: adaptLogGroups(modules),
	}
}

func adaptLogGroups(modules terraform.Modules) []cloudwatch.LogGroup {
	var logGroups []cloudwatch.LogGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_log_group") {
			logGroups = append(logGroups, adaptLogGroup(resource, module))
		}
	}
	return logGroups
}

func adaptLogGroup(resource *terraform.Block, module *terraform.Module) cloudwatch.LogGroup {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	if keyBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource); err == nil {
		KMSKeyIDVal = types.String(keyBlock.FullName(), keyBlock.GetMetadata())
	}

	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return cloudwatch.LogGroup{
		Metadata:        resource.GetMetadata(),
		Arn:             types.StringDefault("", resource.GetMetadata()),
		Name:            nameVal,
		KMSKeyID:        KMSKeyIDVal,
		RetentionInDays: retentionInDaysVal,
		MetricFilters:   nil,
	}
}
