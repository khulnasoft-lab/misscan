package ec2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/owenrumney/squealer/pkg/squealer"
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

func (i *Instance) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *Instance) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}

func (i *Instance) HasSensitiveInformationInUserData() bool {
	scanner := squealer.NewStringScanner()
	return scanner.Scan(i.UserData.Value()).TransgressionFound
}
