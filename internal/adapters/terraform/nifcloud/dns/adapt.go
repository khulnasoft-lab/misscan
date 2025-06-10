package dns

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/dns"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
