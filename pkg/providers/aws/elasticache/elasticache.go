package elasticache

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	Metadata               misscanTypes.Metadata
	Engine                 misscanTypes.StringValue
	NodeType               misscanTypes.StringValue
	SnapshotRetentionLimit misscanTypes.IntValue // days
}

type ReplicationGroup struct {
	Metadata                 misscanTypes.Metadata
	TransitEncryptionEnabled misscanTypes.BoolValue
	AtRestEncryptionEnabled  misscanTypes.BoolValue
}

type SecurityGroup struct {
	Metadata    misscanTypes.Metadata
	Description misscanTypes.StringValue
}
