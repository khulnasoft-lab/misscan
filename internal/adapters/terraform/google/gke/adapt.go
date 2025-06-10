package gke

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/google/uuid"
	"github.com/zclconf/go-cty/cty"
)

func Adapt(modules terraform.Modules) gke.GKE {
	return gke.GKE{
		Clusters: (&adapter{
			modules:    modules,
			clusterMap: make(map[string]gke.Cluster),
		}).adaptClusters(),
	}
}

type adapter struct {
	modules    terraform.Modules
	clusterMap map[string]gke.Cluster
}

func (a *adapter) adaptClusters() []gke.Cluster {
	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("google_container_cluster") {
			a.adaptCluster(resource, module)
		}
	}

	a.adaptNodePools()

	for id, cluster := range a.clusterMap {
		if len(cluster.NodePools) > 0 {
			cluster.NodeConfig = cluster.NodePools[0].NodeConfig
			a.clusterMap[id] = cluster
		}
	}

	var clusters []gke.Cluster
	for _, cluster := range a.clusterMap {
		clusters = append(clusters, cluster)
	}
	return clusters
}

func (a *adapter) adaptCluster(resource *terraform.Block, module *terraform.Module) {

	cluster := gke.Cluster{
		Metadata:  resource.GetMetadata(),
		NodePools: nil,
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: resource.GetMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, resource.GetMetadata()),
			CIDRs:    []misscanTypes.StringValue{},
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		PrivateCluster: gke.PrivateCluster{
			Metadata:           resource.GetMetadata(),
			EnablePrivateNodes: misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		LoggingService:    misscanTypes.StringDefault("logging.googleapis.com/kubernetes", resource.GetMetadata()),
		MonitoringService: misscanTypes.StringDefault("monitoring.googleapis.com/kubernetes", resource.GetMetadata()),
		PodSecurityPolicy: gke.PodSecurityPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuth: gke.MasterAuth{
			Metadata: resource.GetMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         resource.GetMetadata(),
				IssueCertificate: misscanTypes.BoolDefault(false, resource.GetMetadata()),
			},
			Username: misscanTypes.StringDefault("", resource.GetMetadata()),
			Password: misscanTypes.StringDefault("", resource.GetMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  resource.GetMetadata(),
			ImageType: misscanTypes.StringDefault("", resource.GetMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     resource.GetMetadata(),
				NodeMetadata: misscanTypes.StringDefault("", resource.GetMetadata()),
			},
			ServiceAccount:        misscanTypes.StringDefault("", resource.GetMetadata()),
			EnableLegacyEndpoints: misscanTypes.BoolDefault(true, resource.GetMetadata()),
		},
		EnableShieldedNodes:   misscanTypes.BoolDefault(true, resource.GetMetadata()),
		EnableLegacyABAC:      misscanTypes.BoolDefault(false, resource.GetMetadata()),
		ResourceLabels:        misscanTypes.MapDefault(make(map[string]string), resource.GetMetadata()),
		RemoveDefaultNodePool: misscanTypes.BoolDefault(false, resource.GetMetadata()),
		EnableAutpilot:        misscanTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if allocBlock := resource.GetBlock("ip_allocation_policy"); allocBlock.IsNotNil() {
		cluster.IPAllocationPolicy.Metadata = allocBlock.GetMetadata()
		cluster.IPAllocationPolicy.Enabled = misscanTypes.Bool(true, allocBlock.GetMetadata())
	}

	if blocks := resource.GetBlocks("master_authorized_networks_config"); len(blocks) > 0 {
		cluster.MasterAuthorizedNetworks = adaptMasterAuthNetworksAsBlocks(resource, blocks)
	}

	if policyBlock := resource.GetBlock("network_policy"); policyBlock.IsNotNil() {
		enabledAttr := policyBlock.GetAttribute("enabled")
		cluster.NetworkPolicy.Metadata = policyBlock.GetMetadata()
		cluster.NetworkPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, policyBlock)
	}

	if privBlock := resource.GetBlock("private_cluster_config"); privBlock.IsNotNil() {
		privateNodesEnabledAttr := privBlock.GetAttribute("enable_private_nodes")
		cluster.PrivateCluster.Metadata = privBlock.GetMetadata()
		cluster.PrivateCluster.EnablePrivateNodes = privateNodesEnabledAttr.AsBoolValueOrDefault(false, privBlock)
	}

	loggingAttr := resource.GetAttribute("logging_service")
	cluster.LoggingService = loggingAttr.AsStringValueOrDefault("logging.googleapis.com/kubernetes", resource)
	monitoringServiceAttr := resource.GetAttribute("monitoring_service")
	cluster.MonitoringService = monitoringServiceAttr.AsStringValueOrDefault("monitoring.googleapis.com/kubernetes", resource)

	if policyBlock := resource.GetBlock("pod_security_policy_config"); policyBlock.IsNotNil() {
		enabledAttr := policyBlock.GetAttribute("enabled")
		cluster.PodSecurityPolicy.Metadata = policyBlock.GetMetadata()
		cluster.PodSecurityPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, policyBlock)
	}

	if masterBlock := resource.GetBlock("master_auth"); masterBlock.IsNotNil() {
		cluster.MasterAuth = adaptMasterAuth(masterBlock)
	}

	if configBlock := resource.GetBlock("node_config"); configBlock.IsNotNil() {
		if configBlock.GetBlock("metadata").IsNotNil() {
			cluster.NodeConfig.Metadata = configBlock.GetBlock("metadata").GetMetadata()
		}
		cluster.NodeConfig = adaptNodeConfig(configBlock)
	}

	cluster.EnableShieldedNodes = resource.GetAttribute("enable_shielded_nodes").AsBoolValueOrDefault(true, resource)

	enableLegacyABACAttr := resource.GetAttribute("enable_legacy_abac")
	cluster.EnableLegacyABAC = enableLegacyABACAttr.AsBoolValueOrDefault(false, resource)

	cluster.EnableAutpilot = resource.GetAttribute("enable_autopilot").AsBoolValueOrDefault(false, resource)

	resourceLabelsAttr := resource.GetAttribute("resource_labels")
	if resourceLabelsAttr.IsNotNil() {
		resourceLabels := make(map[string]string)
		_ = resourceLabelsAttr.Each(func(key, val cty.Value) {
			if key.Type() == cty.String && val.Type() == cty.String {
				resourceLabels[key.AsString()] = val.AsString()
			}
		})
		cluster.ResourceLabels = misscanTypes.Map(resourceLabels, resourceLabelsAttr.GetMetadata())
	}

	cluster.RemoveDefaultNodePool = resource.GetAttribute("remove_default_node_pool").AsBoolValueOrDefault(false, resource)

	a.clusterMap[resource.ID()] = cluster
}

func (a *adapter) adaptNodePools() {
	for _, nodePoolBlock := range a.modules.GetResourcesByType("google_container_node_pool") {
		a.adaptNodePool(nodePoolBlock)
	}
}

func (a *adapter) adaptNodePool(resource *terraform.Block) {
	nodeConfig := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: misscanTypes.StringDefault("", resource.GetMetadata()),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: misscanTypes.StringDefault("", resource.GetMetadata()),
		},
		ServiceAccount:        misscanTypes.StringDefault("", resource.GetMetadata()),
		EnableLegacyEndpoints: misscanTypes.BoolDefault(true, resource.GetMetadata()),
	}

	management := gke.Management{
		Metadata:          resource.GetMetadata(),
		EnableAutoRepair:  misscanTypes.BoolDefault(false, resource.GetMetadata()),
		EnableAutoUpgrade: misscanTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if resource.HasChild("management") {
		management.Metadata = resource.GetBlock("management").GetMetadata()

		autoRepairAttr := resource.GetBlock("management").GetAttribute("auto_repair")
		management.EnableAutoRepair = autoRepairAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))

		autoUpgradeAttr := resource.GetBlock("management").GetAttribute("auto_upgrade")
		management.EnableAutoUpgrade = autoUpgradeAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))
	}

	if resource.HasChild("node_config") {
		nodeConfig = adaptNodeConfig(resource.GetBlock("node_config"))
	}

	nodePool := gke.NodePool{
		Metadata:   resource.GetMetadata(),
		Management: management,
		NodeConfig: nodeConfig,
	}

	clusterAttr := resource.GetAttribute("cluster")
	if referencedCluster, err := a.modules.GetReferencedBlock(clusterAttr, resource); err == nil {
		if referencedCluster.TypeLabel() == "google_container_cluster" {
			if cluster, ok := a.clusterMap[referencedCluster.ID()]; ok {
				cluster.NodePools = append(cluster.NodePools, nodePool)
				a.clusterMap[referencedCluster.ID()] = cluster
				return
			}
		}
	}

	// we didn't find a cluster to put the nodepool in, so create a placeholder
	a.clusterMap[uuid.NewString()] = gke.Cluster{
		Metadata:  misscanTypes.NewUnmanagedMetadata(),
		NodePools: []gke.NodePool{nodePool},
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			CIDRs:    nil,
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		},
		PrivateCluster: gke.PrivateCluster{
			Metadata:           misscanTypes.NewUnmanagedMetadata(),
			EnablePrivateNodes: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		},
		LoggingService:    misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
		MonitoringService: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
		PodSecurityPolicy: gke.PodSecurityPolicy{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		},
		MasterAuth: gke.MasterAuth{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         misscanTypes.NewUnmanagedMetadata(),
				IssueCertificate: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			},
			Username: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			Password: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  misscanTypes.NewUnmanagedMetadata(),
			ImageType: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     misscanTypes.NewUnmanagedMetadata(),
				NodeMetadata: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			},
			ServiceAccount:        misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			EnableLegacyEndpoints: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		},
		EnableShieldedNodes:   misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		EnableLegacyABAC:      misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		ResourceLabels:        misscanTypes.MapDefault(nil, misscanTypes.NewUnmanagedMetadata()),
		RemoveDefaultNodePool: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		EnableAutpilot:        misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
	}
}

func adaptNodeConfig(resource *terraform.Block) gke.NodeConfig {

	config := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: resource.GetAttribute("image_type").AsStringValueOrDefault("", resource),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: misscanTypes.StringDefault("UNSPECIFIED", resource.GetMetadata()),
		},
		ServiceAccount:        resource.GetAttribute("service_account").AsStringValueOrDefault("", resource),
		EnableLegacyEndpoints: misscanTypes.BoolDefault(true, resource.GetMetadata()),
	}

	if metadata := resource.GetAttribute("metadata"); metadata.IsNotNil() {
		legacyMetadata := metadata.MapValue("disable-legacy-endpoints")
		if legacyMetadata.IsWhollyKnown() && legacyMetadata.Type() == cty.Bool {
			config.EnableLegacyEndpoints = misscanTypes.Bool(legacyMetadata.False(), metadata.GetMetadata())
		}
	}

	workloadBlock := resource.GetBlock("workload_metadata_config")
	if workloadBlock.IsNotNil() {
		config.WorkloadMetadataConfig.Metadata = workloadBlock.GetMetadata()
		modeAttr := workloadBlock.GetAttribute("node_metadata")
		if modeAttr.IsNil() {
			modeAttr = workloadBlock.GetAttribute("mode") // try newest version
		}
		config.WorkloadMetadataConfig.NodeMetadata = modeAttr.AsStringValueOrDefault("UNSPECIFIED", workloadBlock)
	}

	return config
}

func adaptMasterAuth(resource *terraform.Block) gke.MasterAuth {
	clientCert := gke.ClientCertificate{
		Metadata:         resource.GetMetadata(),
		IssueCertificate: misscanTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if resource.HasChild("client_certificate_config") {
		clientCertAttr := resource.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
		clientCert.IssueCertificate = clientCertAttr.AsBoolValueOrDefault(false, resource.GetBlock("client_certificate_config"))
		clientCert.Metadata = resource.GetBlock("client_certificate_config").GetMetadata()
	}

	username := resource.GetAttribute("username").AsStringValueOrDefault("", resource)
	password := resource.GetAttribute("password").AsStringValueOrDefault("", resource)

	return gke.MasterAuth{
		Metadata:          resource.GetMetadata(),
		ClientCertificate: clientCert,
		Username:          username,
		Password:          password,
	}
}

func adaptMasterAuthNetworksAsBlocks(parent *terraform.Block, blocks terraform.Blocks) gke.MasterAuthorizedNetworks {
	var cidrs []misscanTypes.StringValue
	for _, block := range blocks {
		for _, cidrBlock := range block.GetBlocks("cidr_blocks") {
			if cidrAttr := cidrBlock.GetAttribute("cidr_block"); cidrAttr.IsNotNil() {
				cidrs = append(cidrs, cidrAttr.AsStringValues()...)
			}
		}
	}
	enabled := misscanTypes.Bool(true, blocks[0].GetMetadata())
	return gke.MasterAuthorizedNetworks{
		Metadata: blocks[0].GetMetadata(),
		Enabled:  enabled,
		CIDRs:    cidrs,
	}
}
