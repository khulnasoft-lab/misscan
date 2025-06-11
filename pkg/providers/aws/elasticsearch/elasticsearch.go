package elasticsearch

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	Metadata               misscanTypes.Metadata
	DomainName             misscanTypes.StringValue
	AccessPolicies         misscanTypes.StringValue
	DedicatedMasterEnabled misscanTypes.BoolValue
	VpcId                  misscanTypes.StringValue
	LogPublishing          LogPublishing
	TransitEncryption      TransitEncryption
	AtRestEncryption       AtRestEncryption
	ServiceSoftwareOptions ServiceSoftwareOptions
	Endpoint               Endpoint
}

type ServiceSoftwareOptions struct {
	Metadata        misscanTypes.Metadata
	CurrentVersion  misscanTypes.StringValue
	NewVersion      misscanTypes.StringValue
	UpdateAvailable misscanTypes.BoolValue
	UpdateStatus    misscanTypes.StringValue
}

type Endpoint struct {
	Metadata     misscanTypes.Metadata
	EnforceHTTPS misscanTypes.BoolValue
	TLSPolicy    misscanTypes.StringValue
}

type LogPublishing struct {
	Metadata              misscanTypes.Metadata
	AuditEnabled          misscanTypes.BoolValue
	CloudWatchLogGroupArn misscanTypes.StringValue
}

type TransitEncryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type AtRestEncryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	KmsKeyId misscanTypes.StringValue
}
