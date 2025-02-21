package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Instance struct {
	Metadata                    misscanTypes.Metadata
	Name                        misscanTypes.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                misscanTypes.BoolValue
	OSLoginEnabled              misscanTypes.BoolValue
	EnableProjectSSHKeyBlocking misscanTypes.BoolValue
	EnableSerialPort            misscanTypes.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	Metadata  misscanTypes.Metadata
	Email     misscanTypes.StringValue
	IsDefault misscanTypes.BoolValue
	Scopes    []misscanTypes.StringValue
}

type NetworkInterface struct {
	Metadata    misscanTypes.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP misscanTypes.BoolValue
	NATIP       misscanTypes.StringValue
}

type ShieldedVMConfig struct {
	Metadata                   misscanTypes.Metadata
	SecureBootEnabled          misscanTypes.BoolValue
	IntegrityMonitoringEnabled misscanTypes.BoolValue
	VTPMEnabled                misscanTypes.BoolValue
}
