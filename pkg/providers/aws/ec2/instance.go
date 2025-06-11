package ec2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Instance struct {
	Metadata        misscanTypes.Metadata
	MetadataOptions MetadataOptions
	UserData        misscanTypes.StringValue
	SecurityGroups  []SecurityGroup
	RootBlockDevice *BlockDevice
	EBSBlockDevices []*BlockDevice
}

type BlockDevice struct {
	Metadata  misscanTypes.Metadata
	Encrypted misscanTypes.BoolValue
}

type MetadataOptions struct {
	Metadata     misscanTypes.Metadata
	HttpTokens   misscanTypes.StringValue
	HttpEndpoint misscanTypes.StringValue
}

func NewInstance(metadata misscanTypes.Metadata) *Instance {
	return &Instance{
		Metadata: metadata,
		MetadataOptions: MetadataOptions{
			Metadata:     metadata,
			HttpTokens:   misscanTypes.StringDefault("optional", metadata),
			HttpEndpoint: misscanTypes.StringDefault("enabled", metadata),
		},
		UserData:        misscanTypes.StringDefault("", metadata),
		SecurityGroups:  []SecurityGroup{},
		RootBlockDevice: nil,
		EBSBlockDevices: nil,
	}
}
