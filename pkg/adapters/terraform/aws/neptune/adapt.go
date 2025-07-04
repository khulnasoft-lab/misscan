package neptune

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/neptune"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) neptune.Neptune {
	return neptune.Neptune{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []neptune.Cluster {
	var clusters []neptune.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_neptune_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) neptune.Cluster {
	cluster := neptune.Cluster{
		Metadata: resource.GetMetadata(),
		Logging: neptune.Logging{
			Metadata: resource.GetMetadata(),
			Audit:    misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		StorageEncrypted: misscanTypes.BoolDefault(false, resource.GetMetadata()),
		KMSKeyID:         misscanTypes.StringDefault("", resource.GetMetadata()),
	}

	if enableLogExportsAttr := resource.GetAttribute("enable_cloudwatch_logs_exports"); enableLogExportsAttr.IsNotNil() {
		cluster.Logging.Metadata = enableLogExportsAttr.GetMetadata()
		if enableLogExportsAttr.Contains("audit") {
			cluster.Logging.Audit = misscanTypes.Bool(true, enableLogExportsAttr.GetMetadata())
		}
	}

	storageEncryptedAttr := resource.GetAttribute("storage_encrypted")
	cluster.StorageEncrypted = storageEncryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyAttr := resource.GetAttribute("kms_key_arn")
	cluster.KMSKeyID = KMSKeyAttr.AsStringValueOrDefault("", resource)

	return cluster
}
