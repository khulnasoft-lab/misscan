package cloudtrail

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type CloudTrail struct {
	Trails []Trail
}

type Trail struct {
	Metadata                  misscanTypes.Metadata
	Name                      misscanTypes.StringValue
	EnableLogFileValidation   misscanTypes.BoolValue
	IsMultiRegion             misscanTypes.BoolValue
	KMSKeyID                  misscanTypes.StringValue
	CloudWatchLogsLogGroupArn misscanTypes.StringValue
	IsLogging                 misscanTypes.BoolValue
	BucketName                misscanTypes.StringValue
	EventSelectors            []EventSelector
}

type EventSelector struct {
	Metadata      misscanTypes.Metadata
	DataResources []DataResource
	ReadWriteType misscanTypes.StringValue // ReadOnly, WriteOnly, All. Default value is All for TF.
}

type DataResource struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue   //  You can specify only the following value: "AWS::S3::Object", "AWS::Lambda::Function" and "AWS::DynamoDB::Table".
	Values   []misscanTypes.StringValue // List of ARNs/partial ARNs - e.g. arn:aws:s3:::<bucket name>/ for all objects in a bucket, arn:aws:s3:::<bucket name>/key for specific objects
}
