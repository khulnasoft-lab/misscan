package eks

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getClusters(ctx parser.FileContext) (clusters []eks.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::EKS::Cluster")

	for _, r := range clusterResources {
		cluster := eks.Cluster{
			Metadata:            r.Metadata(),
			Logging:             getLogging(r),
			Encryption:          getEncryptionConfig(r),
			PublicAccessEnabled: r.GetBoolProperty("ResourcesVpcConfig.EndpointPublicAccess", true),
			PublicAccessCIDRs:   getPublicCIDRs(r),
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getPublicCIDRs(r *parser.Resource) []misscanTypes.StringValue {
	publicAccessCidrs := r.GetProperty("ResourcesVpcConfig.PublicAccessCidrs")
	if publicAccessCidrs.IsNotList() {
		return nil
	}

	var cidrs []misscanTypes.StringValue
	for _, el := range publicAccessCidrs.AsList() {
		cidrs = append(cidrs, el.AsStringValue())
	}

	if len(cidrs) == 0 {
		return []misscanTypes.StringValue{misscanTypes.StringDefault("0.0.0.0/0", r.Metadata())}
	}

	return cidrs
}

func getEncryptionConfig(r *parser.Resource) eks.Encryption {

	encryptionConfigs := r.GetProperty("EncryptionConfig")
	if encryptionConfigs.IsNotList() {
		return eks.Encryption{
			Metadata: r.Metadata(),
		}
	}

	for _, encryptionConfig := range encryptionConfigs.AsList() {
		resources := encryptionConfig.GetProperty("Resources")
		hasSecrets := resources.IsList() && resources.Contains("secrets")
		return eks.Encryption{
			Metadata: encryptionConfig.Metadata(),
			KMSKeyID: encryptionConfig.GetStringProperty("Provider.KeyArn"),
			Secrets:  misscanTypes.Bool(hasSecrets, resources.Metadata()),
		}
	}

	return eks.Encryption{
		Metadata: r.Metadata(),
	}
}

func getLogging(r *parser.Resource) eks.Logging {
	enabledTypes := r.GetProperty("Logging.ClusterLogging.EnabledTypes")
	if enabledTypes.IsNotList() {
		return eks.Logging{
			Metadata: r.Metadata(),
		}
	}

	logging := eks.Logging{
		Metadata: enabledTypes.Metadata(),
	}

	for _, typeConf := range enabledTypes.AsList() {
		switch typ := typeConf.GetProperty("Type"); typ.AsString() {
		case "api":
			logging.API = misscanTypes.Bool(true, typ.Metadata())
		case "audit":
			logging.Audit = misscanTypes.Bool(true, typ.Metadata())
		case "authenticator":
			logging.Authenticator = misscanTypes.Bool(true, typ.Metadata())
		case "controllerManager":
			logging.ControllerManager = misscanTypes.Bool(true, typ.Metadata())
		case "scheduler":
			logging.Scheduler = misscanTypes.Bool(true, typ.Metadata())
		}

	}

	return logging
}
