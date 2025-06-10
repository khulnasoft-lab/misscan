package cloudstack

import (
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/cloudstack/compute"
	"github.com/khulnasoft-lab/misscan/pkg/providers/cloudstack"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
