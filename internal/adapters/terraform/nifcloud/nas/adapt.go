package nas

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) nas.NAS {
	return nas.NAS{
		NASSecurityGroups: adaptNASSecurityGroups(modules),
		NASInstances:      adaptNASInstances(modules),
	}
}
