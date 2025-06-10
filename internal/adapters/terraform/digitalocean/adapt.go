package digitalocean

import (
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/digitalocean/compute"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/digitalocean/spaces"
	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
