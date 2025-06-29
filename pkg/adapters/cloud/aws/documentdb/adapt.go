package documentdb

import (
	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/docdb/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "documentdb"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.DocumentDB.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]documentdb.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []types.DBCluster
	var input api.DescribeDBClustersInput
	for {
		output, err := a.client.DescribeDBClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.DBClusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(cluster types.DBCluster) (*documentdb.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*cluster.DBClusterArn)

	var logExports []misscanTypes.StringValue
	for _, export := range cluster.EnabledCloudwatchLogsExports {
		logExports = append(logExports, misscanTypes.String(export, metadata))
	}

	var kmsKeyId string
	if cluster.KmsKeyId != nil {
		kmsKeyId = *cluster.KmsKeyId
	}

	var identifier string
	if cluster.DBClusterIdentifier != nil {
		identifier = *cluster.DBClusterIdentifier
	}

	var instances []documentdb.Instance
	for _, instance := range cluster.DBClusterMembers {
		output, err := a.client.DescribeDBInstances(a.Context(), &api.DescribeDBInstancesInput{
			DBInstanceIdentifier: instance.DBInstanceIdentifier,
		})
		if err != nil {
			return nil, err
		}
		var kmsKeyId string
		if output.DBInstances[0].KmsKeyId != nil {
			kmsKeyId = *output.DBInstances[0].KmsKeyId
		}
		instances = append(instances, documentdb.Instance{
			Metadata: metadata,
			KMSKeyID: misscanTypes.String(kmsKeyId, metadata),
		})
	}

	return &documentdb.Cluster{
		Metadata:              metadata,
		Identifier:            misscanTypes.String(identifier, metadata),
		EnabledLogExports:     logExports,
		Instances:             instances,
		StorageEncrypted:      misscanTypes.Bool(cluster.StorageEncrypted, metadata),
		KMSKeyID:              misscanTypes.String(kmsKeyId, metadata),
		BackupRetentionPeriod: misscanTypes.Int(int(*cluster.BackupRetentionPeriod), metadata),
	}, nil
}