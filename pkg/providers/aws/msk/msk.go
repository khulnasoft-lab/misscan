package msk

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            misscanTypes.Metadata
	EncryptionInTransit EncryptionInTransit
	EncryptionAtRest    EncryptionAtRest
	Logging             Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	Metadata     misscanTypes.Metadata
	ClientBroker misscanTypes.StringValue
}

type EncryptionAtRest struct {
	Metadata  misscanTypes.Metadata
	KMSKeyARN misscanTypes.StringValue
	Enabled   misscanTypes.BoolValue
}

type Logging struct {
	Metadata misscanTypes.Metadata
	Broker   BrokerLogging
}

type BrokerLogging struct {
	Metadata   misscanTypes.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type CloudwatchLogging struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type FirehoseLogging struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}
