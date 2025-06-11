package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	Metadata   misscanTypes.Metadata
	CustomData misscanTypes.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	Metadata misscanTypes.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	Metadata misscanTypes.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	Metadata                      misscanTypes.Metadata
	DisablePasswordAuthentication misscanTypes.BoolValue
}

type ManagedDisk struct {
	Metadata   misscanTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}
