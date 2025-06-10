package eks

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) eks.EKS {
	return eks.EKS{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []eks.Cluster {
	var clusters []eks.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_eks_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) eks.Cluster {

	cluster := eks.Cluster{
		Metadata: resource.GetMetadata(),
		Logging: eks.Logging{
			Metadata:          resource.GetMetadata(),
			API:               misscanTypes.BoolDefault(false, resource.GetMetadata()),
			Audit:             misscanTypes.BoolDefault(false, resource.GetMetadata()),
			Authenticator:     misscanTypes.BoolDefault(false, resource.GetMetadata()),
			ControllerManager: misscanTypes.BoolDefault(false, resource.GetMetadata()),
			Scheduler:         misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		Encryption: eks.Encryption{
			Metadata: resource.GetMetadata(),
			Secrets:  misscanTypes.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: misscanTypes.StringDefault("", resource.GetMetadata()),
		},
		PublicAccessEnabled: misscanTypes.BoolDefault(true, resource.GetMetadata()),
		PublicAccessCIDRs:   nil,
	}

	if logTypesAttr := resource.GetAttribute("enabled_cluster_log_types"); logTypesAttr.IsNotNil() {
		cluster.Logging.Metadata = logTypesAttr.GetMetadata()
		for _, logType := range logTypesAttr.AsStringValues() {
			switch logType.Value() {
			case "api":
				cluster.Logging.API = misscanTypes.Bool(true, logTypesAttr.GetMetadata())
			case "audit":
				cluster.Logging.Audit = misscanTypes.Bool(true, logTypesAttr.GetMetadata())
			case "authenticator":
				cluster.Logging.Authenticator = misscanTypes.Bool(true, logTypesAttr.GetMetadata())
			case "controllerManager":
				cluster.Logging.ControllerManager = misscanTypes.Bool(true, logTypesAttr.GetMetadata())
			case "scheduler":
				cluster.Logging.Scheduler = misscanTypes.Bool(true, logTypesAttr.GetMetadata())
			}
		}
	}

	if encryptBlock := resource.GetBlock("encryption_config"); encryptBlock.IsNotNil() {
		cluster.Encryption.Metadata = encryptBlock.GetMetadata()
		resourcesAttr := encryptBlock.GetAttribute("resources")
		if resourcesAttr.Contains("secrets") {
			cluster.Encryption.Secrets = misscanTypes.Bool(true, resourcesAttr.GetMetadata())
		}
		if providerBlock := encryptBlock.GetBlock("provider"); providerBlock.IsNotNil() {
			keyArnAttr := providerBlock.GetAttribute("key_arn")
			cluster.Encryption.KMSKeyID = keyArnAttr.AsStringValueOrDefault("", providerBlock)
		}
	}

	if vpcBlock := resource.GetBlock("vpc_config"); vpcBlock.IsNotNil() {
		publicAccessAttr := vpcBlock.GetAttribute("endpoint_public_access")
		cluster.PublicAccessEnabled = publicAccessAttr.AsBoolValueOrDefault(true, vpcBlock)

		publicAccessCidrsAttr := vpcBlock.GetAttribute("public_access_cidrs")
		cidrList := publicAccessCidrsAttr.AsStringValues()
		for _, cidr := range cidrList {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, cidr)
		}
		if len(cidrList) == 0 {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, misscanTypes.StringDefault("0.0.0.0/0", vpcBlock.GetMetadata()))
		}
	}

	return cluster
}
