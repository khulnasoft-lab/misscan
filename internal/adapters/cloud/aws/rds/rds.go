package rds

import (
	aws2 "github.com/khulnasoft-lab/misscan/internal/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	rdsApi "github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type adapter struct {
	*aws2.RootAdapter
	api *rdsApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Name() string {
	return "rds"
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = rdsApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.RDS.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	state.AWS.RDS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.RDS.Classic, err = a.getClassic()
	if err != nil {
		a.Debug("Failed to retrieve classic resource: %s", err)
		return nil
	}

	state.AWS.RDS.Snapshots, err = a.getSnapshots()
	if err != nil {
		return err
	}

	state.AWS.RDS.ParameterGroups, err = a.getParameterGroups()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSnapshots() (snapshots []rds.Snapshots, err error) {
	a.Tracker().SetServiceLabel("Discovering Snapshots...")
	var apiDBSnapshots []types.DBSnapshot
	var input rdsApi.DescribeDBSnapshotsInput

	for {
		output, err := a.api.DescribeDBSnapshots(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiDBSnapshots = append(apiDBSnapshots, output.DBSnapshots...)
		a.Tracker().SetTotalResources(len(apiDBSnapshots))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS DB snapshots...")
	return concurrency.Adapt(apiDBSnapshots, a.RootAdapter, a.adaptDBSnapshots), nil
}

func (a *adapter) getInstances() (instances []rds.Instance, err error) {

	a.Tracker().SetServiceLabel("Discovering RDS instances...")
	var apiDBInstances []types.DBInstance
	var input rdsApi.DescribeDBInstancesInput

	for {
		output, err := a.api.DescribeDBInstances(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDBInstances = append(apiDBInstances, output.DBInstances...)
		a.Tracker().SetTotalResources(len(apiDBInstances))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting RDS instances...")
	return concurrency.Adapt(apiDBInstances, a.RootAdapter, a.adaptDBInstance), nil
}

func (a *adapter) getParameterGroups() (parameter []rds.ParameterGroups, err error) {
	a.Tracker().SetServiceLabel(" Parameter...")
	var apiParameter []types.DBParameterGroup
	var input rdsApi.DescribeDBParameterGroupsInput

	for {
		output, err := a.api.DescribeDBParameterGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiParameter = append(apiParameter, output.DBParameterGroups...)
		a.Tracker().SetTotalResources(len(apiParameter))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting RDS Parameters Groups")
	return concurrency.Adapt(apiParameter, a.RootAdapter, a.adaptParameterGroup), nil
}

func (a *adapter) getClusters() (clusters []rds.Cluster, err error) {

	a.Tracker().SetServiceLabel("Discovering RDS clusters...")
	var apDBClusters []types.DBCluster
	var input rdsApi.DescribeDBClustersInput

	for {
		output, err := a.api.DescribeDBClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apDBClusters = append(apDBClusters, output.DBClusters...)
		a.Tracker().SetTotalResources(len(apDBClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS clusters...")
	return concurrency.Adapt(apDBClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) getClassic() (rds.Classic, error) {

	classic := rds.Classic{
		DBSecurityGroups: nil,
	}

	a.Tracker().SetServiceLabel("Discovering RDS classic instances...")
	var apiDBSGs []types.DBSecurityGroup
	var input rdsApi.DescribeDBSecurityGroupsInput

	for {
		output, err := a.api.DescribeDBSecurityGroups(a.Context(), &input)
		if err != nil {
			return classic, err
		}
		apiDBSGs = append(apiDBSGs, output.DBSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiDBSGs))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS clusters...")
	sgs := concurrency.Adapt(apiDBSGs, a.RootAdapter, a.adaptClassic)

	classic.DBSecurityGroups = sgs
	return classic, nil
}

func (a *adapter) adaptDBInstance(dbInstance types.DBInstance) (*rds.Instance, error) {

	dbInstanceMetadata := a.CreateMetadata("db:" + *dbInstance.DBInstanceIdentifier)

	var TagList []rds.TagList
	if dbInstance.TagList != nil {
		for range dbInstance.TagList {
			TagList = append(TagList, rds.TagList{
				Metadata: dbInstanceMetadata,
			})
		}
	}

	var EnabledCloudwatchLogsExports []misscanTypes.StringValue
	for _, ecwe := range dbInstance.EnabledCloudwatchLogsExports {
		EnabledCloudwatchLogsExports = append(EnabledCloudwatchLogsExports, misscanTypes.String(ecwe, dbInstanceMetadata))
	}

	var ReadReplicaDBInstanceIdentifiers []misscanTypes.StringValue
	for _, rrdbi := range dbInstance.EnabledCloudwatchLogsExports {
		ReadReplicaDBInstanceIdentifiers = append(ReadReplicaDBInstanceIdentifiers, misscanTypes.String(rrdbi, dbInstanceMetadata))
	}

	engine := rds.EngineAurora
	if dbInstance.Engine != nil {
		engine = *dbInstance.Engine
	}

	instance := &rds.Instance{
		Metadata:                  dbInstanceMetadata,
		BackupRetentionPeriodDays: misscanTypes.IntFromInt32(dbInstance.BackupRetentionPeriod, dbInstanceMetadata),
		ReplicationSourceARN:      misscanTypes.String(aws.ToString(dbInstance.ReadReplicaSourceDBInstanceIdentifier), dbInstanceMetadata),
		PerformanceInsights: getPerformanceInsights(
			dbInstance.PerformanceInsightsEnabled,
			dbInstance.PerformanceInsightsKMSKeyId,
			dbInstanceMetadata,
		),
		Encryption:                       getInstanceEncryption(dbInstance.StorageEncrypted, dbInstance.KmsKeyId, dbInstanceMetadata),
		PublicAccess:                     misscanTypes.Bool(dbInstance.PubliclyAccessible, dbInstanceMetadata),
		Engine:                           misscanTypes.String(engine, dbInstanceMetadata),
		IAMAuthEnabled:                   misscanTypes.Bool(dbInstance.IAMDatabaseAuthenticationEnabled, dbInstanceMetadata),
		DeletionProtection:               misscanTypes.Bool(dbInstance.DeletionProtection, dbInstanceMetadata),
		DBInstanceArn:                    misscanTypes.String(*dbInstance.DBInstanceArn, dbInstanceMetadata),
		StorageEncrypted:                 misscanTypes.Bool(dbInstance.StorageEncrypted, dbInstanceMetadata),
		DBInstanceIdentifier:             misscanTypes.String(*dbInstance.DBInstanceIdentifier, dbInstanceMetadata),
		TagList:                          TagList,
		EnabledCloudwatchLogsExports:     EnabledCloudwatchLogsExports,
		EngineVersion:                    misscanTypes.String(engine, dbInstanceMetadata),
		AutoMinorVersionUpgrade:          misscanTypes.Bool(dbInstance.AutoMinorVersionUpgrade, dbInstanceMetadata),
		MultiAZ:                          misscanTypes.Bool(dbInstance.MultiAZ, dbInstanceMetadata),
		PubliclyAccessible:               misscanTypes.Bool(dbInstance.PubliclyAccessible, dbInstanceMetadata),
		LatestRestorableTime:             misscanTypes.TimeUnresolvable(dbInstanceMetadata),
		ReadReplicaDBInstanceIdentifiers: ReadReplicaDBInstanceIdentifiers,
	}

	return instance, nil
}

func (a *adapter) adaptCluster(dbCluster types.DBCluster) (*rds.Cluster, error) {

	dbClusterMetadata := a.CreateMetadata("cluster:" + *dbCluster.DBClusterIdentifier)

	engine := rds.EngineAurora
	if dbCluster.Engine != nil {
		engine = *dbCluster.Engine
	}

	var availabilityZones []misscanTypes.StringValue
	for _, az := range dbCluster.AvailabilityZones {
		availabilityZones = append(availabilityZones, misscanTypes.String(az, dbClusterMetadata))
	}

	cluster := &rds.Cluster{
		Metadata:                  dbClusterMetadata,
		BackupRetentionPeriodDays: misscanTypes.IntFromInt32(aws.ToInt32(dbCluster.BackupRetentionPeriod), dbClusterMetadata),
		ReplicationSourceARN:      misscanTypes.String(aws.ToString(dbCluster.ReplicationSourceIdentifier), dbClusterMetadata),
		PerformanceInsights: getPerformanceInsights(
			dbCluster.PerformanceInsightsEnabled,
			dbCluster.PerformanceInsightsKMSKeyId,
			dbClusterMetadata,
		),
		Encryption:           getInstanceEncryption(dbCluster.StorageEncrypted, dbCluster.KmsKeyId, dbClusterMetadata),
		PublicAccess:         misscanTypes.Bool(aws.ToBool(dbCluster.PubliclyAccessible), dbClusterMetadata),
		Engine:               misscanTypes.String(engine, dbClusterMetadata),
		LatestRestorableTime: misscanTypes.TimeUnresolvable(dbClusterMetadata),
		AvailabilityZones:    availabilityZones,
		DeletionProtection:   misscanTypes.Bool(aws.ToBool(dbCluster.DeletionProtection), dbClusterMetadata),
		SkipFinalSnapshot:    misscanTypes.Bool(false, dbClusterMetadata),
	}

	return cluster, nil
}

func (a *adapter) adaptParameterGroup(dbParameterGroup types.DBParameterGroup) (*rds.ParameterGroups, error) {

	metadata := a.CreateMetadata("dbparametergroup:" + *dbParameterGroup.DBParameterGroupArn)
	var parameter []rds.Parameters
	output, err := a.api.DescribeDBParameters(a.Context(), &rdsApi.DescribeDBParametersInput{
		DBParameterGroupName: dbParameterGroup.DBParameterGroupName,
	})
	if err != nil {
		return nil, err
	}

	for _, r := range output.Parameters {

		parameterName := misscanTypes.StringDefault("", metadata)
		if r.ParameterName != nil {
			parameterName = misscanTypes.String(*r.ParameterName, metadata)
		}

		parmeterValue := misscanTypes.StringDefault("", metadata)
		if r.ParameterValue != nil {
			parmeterValue = misscanTypes.String(*r.ParameterValue, metadata)
		}
		parameter = append(parameter, rds.Parameters{
			Metadata:       metadata,
			ParameterName:  parameterName,
			ParameterValue: parmeterValue,
		})
	}

	return &rds.ParameterGroups{
		Metadata:               metadata,
		Parameters:             parameter,
		DBParameterGroupName:   misscanTypes.String(*dbParameterGroup.DBParameterGroupName, metadata),
		DBParameterGroupFamily: misscanTypes.String(*dbParameterGroup.DBParameterGroupFamily, metadata),
	}, nil

}

func (a *adapter) adaptDBSnapshots(dbSnapshots types.DBSnapshot) (*rds.Snapshots, error) {
	metadata := a.CreateMetadata("dbsnapshots" + *dbSnapshots.DBSnapshotArn)

	var SnapshotAttributes []rds.DBSnapshotAttributes
	output, err := a.api.DescribeDBSnapshotAttributes(a.Context(), &rdsApi.DescribeDBSnapshotAttributesInput{
		DBSnapshotIdentifier: dbSnapshots.DBSnapshotIdentifier,
	})
	if err != nil {
		return nil, err
	}
	if output.DBSnapshotAttributesResult != nil {
		for _, r := range output.DBSnapshotAttributesResult.DBSnapshotAttributes {

			var AV []misscanTypes.StringValue
			if r.AttributeValues != nil {
				for _, Values := range r.AttributeValues {
					AV = append(AV, misscanTypes.String(Values, metadata))
				}
			}
			SnapshotAttributes = append(SnapshotAttributes, rds.DBSnapshotAttributes{
				Metadata:        metadata,
				AttributeValues: AV,
			})
		}

	}

	snapshots := &rds.Snapshots{
		Metadata:             metadata,
		DBSnapshotIdentifier: misscanTypes.String(*dbSnapshots.DBSnapshotIdentifier, metadata),
		DBSnapshotArn:        misscanTypes.String(*dbSnapshots.DBSnapshotArn, metadata),
		Encrypted:            misscanTypes.Bool(dbSnapshots.Encrypted, metadata),
		KmsKeyId:             misscanTypes.String("", metadata),
		SnapshotAttributes:   SnapshotAttributes,
	}

	// KMSKeyID is only set if Encryption is enabled
	if snapshots.Encrypted.IsTrue() {
		snapshots.KmsKeyId = misscanTypes.StringDefault(*dbSnapshots.KmsKeyId, metadata)
	}

	return snapshots, nil
}

func (a *adapter) adaptClassic(dbSecurityGroup types.DBSecurityGroup) (*rds.DBSecurityGroup, error) {

	dbSecurityGroupMetadata := a.CreateMetadata("secgrp:" + *dbSecurityGroup.DBSecurityGroupName)

	dbsg := &rds.DBSecurityGroup{
		Metadata: dbSecurityGroupMetadata,
	}

	return dbsg, nil
}

func getInstanceEncryption(storageEncrypted bool, kmsKeyID *string, metadata misscanTypes.Metadata) rds.Encryption {
	encryption := rds.Encryption{
		Metadata:       metadata,
		EncryptStorage: misscanTypes.BoolDefault(storageEncrypted, metadata),
		KMSKeyID:       misscanTypes.StringDefault("", metadata),
	}

	if kmsKeyID != nil {
		encryption.KMSKeyID = misscanTypes.String(*kmsKeyID, metadata)
	}

	return encryption
}

func getPerformanceInsights(enabled *bool, kmsKeyID *string, metadata misscanTypes.Metadata) rds.PerformanceInsights {
	performanceInsights := rds.PerformanceInsights{
		Metadata: metadata,
		Enabled:  misscanTypes.BoolDefault(false, metadata),
		KMSKeyID: misscanTypes.StringDefault("", metadata),
	}
	if enabled != nil {
		performanceInsights.Enabled = misscanTypes.Bool(*enabled, metadata)
	}
	if kmsKeyID != nil {
		performanceInsights.KMSKeyID = misscanTypes.String(*kmsKeyID, metadata)
	}

	return performanceInsights
}
