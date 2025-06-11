package dynamodb

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/dynamodb"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourcesByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Metadata: r.Metadata(),
				Enabled:  misscanTypes.BoolDefault(false, r.Metadata()),
				KMSKeyID: misscanTypes.StringDefault("", r.Metadata()),
			},
			PointInTimeRecovery: misscanTypes.BoolUnresolvable(r.Metadata()),
		}

		if sseProp := r.GetProperty("SSESpecification"); sseProp.IsNotNil() {
			cluster.ServerSideEncryption = dynamodb.ServerSideEncryption{
				Metadata: sseProp.Metadata(),
				Enabled:  r.GetBoolProperty("SSESpecification.SSEEnabled"),
				KMSKeyID: misscanTypes.StringUnresolvable(sseProp.Metadata()),
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
