package ec2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type LaunchConfiguration struct {
	Metadata          misscanTypes.Metadata
	Name              misscanTypes.StringValue
	AssociatePublicIP misscanTypes.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []*BlockDevice
	MetadataOptions   MetadataOptions
	UserData          misscanTypes.StringValue
}

type LaunchTemplate struct {
	Metadata misscanTypes.Metadata
	Name     misscanTypes.StringValue
	Instance
}
