package dynamodb

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
}

type DAXCluster struct {
	Metadata             misscanTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  misscanTypes.BoolValue
}

type Table struct {
	Metadata             misscanTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  misscanTypes.BoolValue
}

type ServerSideEncryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	KMSKeyID misscanTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"
