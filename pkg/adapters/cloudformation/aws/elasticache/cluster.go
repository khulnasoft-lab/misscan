package elasticache

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elasticache"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

func getClusterGroups(ctx parser.FileContext) (clusters []elasticache.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::ElastiCache::CacheCluster")

	for _, r := range clusterResources {
		cluster := elasticache.Cluster{
			Metadata:               r.Metadata(),
			Engine:                 r.GetStringProperty("Engine"),
			NodeType:               r.GetStringProperty("CacheNodeType"),
			SnapshotRetentionLimit: r.GetIntProperty("SnapshotRetentionLimit"),
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
