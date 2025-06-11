package redshift

import (
	"strings"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/redshift"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshift/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "redshift"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Redshift.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.Redshift.ReservedNodes, err = a.getReservedNodes()
	if err != nil {
		return err
	}

	state.AWS.Redshift.ClusterParameters, err = a.getParameters()
	if err != nil {
		return err
	}

	// this can error is classic resources are used where disabled
	state.AWS.Redshift.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		a.Debug("Failed to adapt security groups: %s", err)
		return nil
	}

	return nil
}

func (a *adapter) getClusters() ([]redshift.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []types.Cluster
	var input api.DescribeClustersInput
	for {
		output, err := a.api.DescribeClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.Clusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster types.Cluster) (*redshift.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.ClusterNamespaceArn)

	output, err := a.api.DescribeLoggingStatus(a.Context(), &api.DescribeLoggingStatusInput{
		ClusterIdentifier: apiCluster.ClusterIdentifier,
	})
	if err != nil {
		output = nil
	}

	var loggingenabled bool
	if output != nil {
		loggingenabled = output.LoggingEnabled
	}

	var kmsKeyId string
	if apiCluster.KmsKeyId != nil {
		kmsKeyId = *apiCluster.KmsKeyId
	}

	var subnetGroupName string
	if apiCluster.ClusterSubnetGroupName != nil {
		subnetGroupName = *apiCluster.ClusterSubnetGroupName
	}

	var port int
	if apiCluster.Endpoint != nil {
		port = int(apiCluster.Endpoint.Port)
	}

	return &redshift.Cluster{
		Metadata:                         metadata,
		ClusterIdentifier:                misscanTypes.String(*apiCluster.ClusterIdentifier, metadata),
		AllowVersionUpgrade:              misscanTypes.Bool(apiCluster.AllowVersionUpgrade, metadata),
		NumberOfNodes:                    misscanTypes.Int(int(apiCluster.NumberOfNodes), metadata),
		NodeType:                         misscanTypes.String(*apiCluster.NodeType, metadata),
		PubliclyAccessible:               misscanTypes.Bool(apiCluster.PubliclyAccessible, metadata),
		VpcId:                            misscanTypes.String(*apiCluster.VpcId, metadata),
		MasterUsername:                   misscanTypes.String(*apiCluster.MasterUsername, metadata),
		AutomatedSnapshotRetentionPeriod: misscanTypes.Int(int(apiCluster.ManualSnapshotRetentionPeriod), metadata),
		LoggingEnabled:                   misscanTypes.Bool(loggingenabled, metadata),
		EndPoint: redshift.EndPoint{
			Metadata: metadata,
			Port:     misscanTypes.Int(port, metadata),
		},
		Encryption: redshift.Encryption{
			Metadata: metadata,
			Enabled:  misscanTypes.Bool(apiCluster.Encrypted, metadata),
			KMSKeyID: misscanTypes.String(kmsKeyId, metadata),
		},
		SubnetGroupName: misscanTypes.String(subnetGroupName, metadata),
	}, nil
}

func (a *adapter) getSecurityGroups() ([]redshift.SecurityGroup, error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var apiGroups []types.ClusterSecurityGroup
	var input api.DescribeClusterSecurityGroupsInput
	for {
		output, err := a.api.DescribeClusterSecurityGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiGroups = append(apiGroups, output.ClusterSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiGroups))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting security groups...")
	return concurrency.Adapt(apiGroups, a.RootAdapter, a.adaptSecurityGroup), nil
}

func (a *adapter) adaptSecurityGroup(apiSG types.ClusterSecurityGroup) (*redshift.SecurityGroup, error) {

	metadata := a.CreateMetadata("securitygroup:" + *apiSG.ClusterSecurityGroupName)

	description := misscanTypes.StringDefault("", metadata)
	if apiSG.Description != nil {
		description = misscanTypes.String(*apiSG.Description, metadata)
	}

	return &redshift.SecurityGroup{
		Metadata:    metadata,
		Description: description,
	}, nil
}

func (a *adapter) getReservedNodes() ([]redshift.ReservedNode, error) {

	a.Tracker().SetServiceLabel("Discovering reserved nodes...")

	var apiReservednodes []types.ReservedNode
	var input api.DescribeReservedNodesInput
	for {
		output, err := a.api.DescribeReservedNodes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiReservednodes = append(apiReservednodes, output.ReservedNodes...)
		a.Tracker().SetTotalResources(len(apiReservednodes))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting reserved node ...")
	return concurrency.Adapt(apiReservednodes, a.RootAdapter, a.adaptnode), nil
}

func (a *adapter) adaptnode(node types.ReservedNode) (*redshift.ReservedNode, error) {
	metadata := a.CreateMetadata(*node.ReservedNodeId)
	return &redshift.ReservedNode{
		Metadata: metadata,
		NodeType: misscanTypes.String(*node.NodeType, metadata),
	}, nil
}

func (a *adapter) getParameters() ([]redshift.ClusterParameter, error) {

	a.Tracker().SetServiceLabel("Discovering cluster parameters ...")

	var apiClusters []types.Parameter
	var input api.DescribeClusterParameterGroupsInput
	output, err := a.api.DescribeClusterParameterGroups(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	for _, group := range output.ParameterGroups {
		groupname := *group.ParameterGroupName
		if !strings.HasPrefix(groupname, "default.redshift") {
			output, err := a.api.DescribeClusterParameters(a.Context(), &api.DescribeClusterParametersInput{
				ParameterGroupName: group.ParameterGroupName,
			})
			if err != nil {
				return nil, err
			}
			apiClusters = append(apiClusters, output.Parameters...)
			a.Tracker().SetTotalResources(len(apiClusters))
			if output.Marker == nil {
				break
			}
			input.Marker = output.Marker
		}

	}

	a.Tracker().SetServiceLabel("Adapting cluster parameters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptParameter), nil
}

func (a *adapter) adaptParameter(parameter types.Parameter) (*redshift.ClusterParameter, error) {

	metadata := a.CreateMetadata(*parameter.ParameterName)

	return &redshift.ClusterParameter{
		Metadata:       metadata,
		ParameterName:  misscanTypes.String(*parameter.ParameterName, metadata),
		ParameterValue: misscanTypes.String(*parameter.ParameterValue, metadata),
	}, nil

}
