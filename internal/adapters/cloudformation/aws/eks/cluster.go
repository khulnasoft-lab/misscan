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
			Metadata: r.Metadata(),
			// Logging not supported for cloudformation https://github.com/aws/containers-roadmap/issues/242
			Logging: eks.Logging{
				Metadata:          r.Metadata(),
				API:               misscanTypes.BoolUnresolvable(r.Metadata()),
				Audit:             misscanTypes.BoolUnresolvable(r.Metadata()),
				Authenticator:     misscanTypes.BoolUnresolvable(r.Metadata()),
				ControllerManager: misscanTypes.BoolUnresolvable(r.Metadata()),
				Scheduler:         misscanTypes.BoolUnresolvable(r.Metadata()),
			},
			Encryption: getEncryptionConfig(r),
			// endpoint protection not supported - https://github.com/aws/containers-roadmap/issues/242
			PublicAccessEnabled: misscanTypes.BoolUnresolvable(r.Metadata()),
			PublicAccessCIDRs:   nil,
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getEncryptionConfig(r *parser.Resource) eks.Encryption {

	encryption := eks.Encryption{
		Metadata: r.Metadata(),
		Secrets:  misscanTypes.BoolDefault(false, r.Metadata()),
		KMSKeyID: misscanTypes.StringDefault("", r.Metadata()),
	}

	if encProp := r.GetProperty("EncryptionConfig"); encProp.IsNotNil() {
		encryption.Metadata = encProp.Metadata()
		encryption.KMSKeyID = encProp.GetStringProperty("Provider.KeyArn")
		resourcesProp := encProp.GetProperty("Resources")
		if resourcesProp.IsList() {
			if resourcesProp.Contains("secrets") {
				encryption.Secrets = misscanTypes.Bool(true, resourcesProp.Metadata())
			}
		}
	}

	return encryption
}
