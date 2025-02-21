package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

type Network struct {
	Metadata    types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
