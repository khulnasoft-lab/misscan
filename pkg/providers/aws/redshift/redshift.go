package redshift

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Redshift struct {
	Clusters          []Cluster
	ReservedNodes     []ReservedNode
	ClusterParameters []ClusterParameter
	SecurityGroups    []SecurityGroup
}

type SecurityGroup struct {
	Metadata    misscanTypes.Metadata
	Description misscanTypes.StringValue
}

type ReservedNode struct {
	Metadata misscanTypes.Metadata
	NodeType misscanTypes.StringValue
}

type ClusterParameter struct {
	Metadata       misscanTypes.Metadata
	ParameterName  misscanTypes.StringValue
	ParameterValue misscanTypes.StringValue
}

type Cluster struct {
	Metadata                         misscanTypes.Metadata
	ClusterIdentifier                misscanTypes.StringValue
	NodeType                         misscanTypes.StringValue
	VpcId                            misscanTypes.StringValue
	NumberOfNodes                    misscanTypes.IntValue
	PubliclyAccessible               misscanTypes.BoolValue
	AllowVersionUpgrade              misscanTypes.BoolValue
	MasterUsername                   misscanTypes.StringValue
	AutomatedSnapshotRetentionPeriod misscanTypes.IntValue
	LoggingEnabled                   misscanTypes.BoolValue
	EndPoint                         EndPoint
	Encryption                       Encryption
	SubnetGroupName                  misscanTypes.StringValue
}

type EndPoint struct {
	Metadata misscanTypes.Metadata
	Port     misscanTypes.IntValue
}

type Encryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	KMSKeyID misscanTypes.StringValue
}
