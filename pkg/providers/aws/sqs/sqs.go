package sqs

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	Metadata   misscanTypes.Metadata
	QueueURL   misscanTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	Metadata          misscanTypes.Metadata
	KMSKeyID          misscanTypes.StringValue
	ManagedEncryption misscanTypes.BoolValue
}
