package eks

import (
	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	eksapi "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
)

type adapter struct {
	*aws.RootAdapter
	api *eksapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "eks"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = eksapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EKS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]eks.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var clusterNames []string
	var input eksapi.ListClustersInput
	for {
		output, err := a.api.ListClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		clusterNames = append(clusterNames, output.Clusters...)
		a.Tracker().SetTotalResources(len(clusterNames))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(clusterNames, a.RootAdapter, a.adaptCluster), nil
}

// nolint
func (a *adapter) adaptCluster(name string) (*eks.Cluster, error) {

	output, err := a.api.DescribeCluster(a.Context(), &eksapi.DescribeClusterInput{
		Name: &name,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*output.Cluster.Arn)

	var publicAccess bool
	var publicCidrs []misscanTypes.StringValue
	if output.Cluster.ResourcesVpcConfig != nil {
		publicAccess = output.Cluster.ResourcesVpcConfig.EndpointPublicAccess
		for _, cidr := range output.Cluster.ResourcesVpcConfig.PublicAccessCidrs {
			publicCidrs = append(publicCidrs, misscanTypes.String(cidr, metadata))
		}
	}

	var encryptionKeyARN string
	var secretsEncrypted bool
	for _, config := range output.Cluster.EncryptionConfig {
		if config.Provider != nil && config.Provider.KeyArn != nil {
			encryptionKeyARN = *config.Provider.KeyArn
		}
		if len(config.Resources) > 0 {
			for _, resource := range config.Resources {
				if resource == "secrets" {
					secretsEncrypted = true
				}
			}
		}
	}

	var logAPI, logAudit, logAuth, logCM, logSched bool
	if output.Cluster.Logging != nil {
		for _, logging := range output.Cluster.Logging.ClusterLogging {
			if logging.Enabled == nil || !*logging.Enabled {
				continue
			}
			for _, logType := range logging.Types {
				switch logType {
				case types.LogTypeApi:
					logAPI = true
				case types.LogTypeAudit:
					logAudit = true
				case types.LogTypeAuthenticator:
					logAuth = true
				case types.LogTypeControllerManager:
					logCM = true
				case types.LogTypeScheduler:
					logSched = true
				}
			}
		}
	}

	return &eks.Cluster{
		Metadata: metadata,
		Logging: eks.Logging{
			Metadata:          metadata,
			API:               misscanTypes.Bool(logAPI, metadata),
			Audit:             misscanTypes.Bool(logAudit, metadata),
			Authenticator:     misscanTypes.Bool(logAuth, metadata),
			ControllerManager: misscanTypes.Bool(logCM, metadata),
			Scheduler:         misscanTypes.Bool(logSched, metadata),
		},
		Encryption: eks.Encryption{
			Metadata: metadata,
			Secrets:  misscanTypes.Bool(secretsEncrypted, metadata),
			KMSKeyID: misscanTypes.String(encryptionKeyARN, metadata),
		},
		PublicAccessEnabled: misscanTypes.Bool(publicAccess, metadata),
		PublicAccessCIDRs:   publicCidrs,
	}, nil
}
