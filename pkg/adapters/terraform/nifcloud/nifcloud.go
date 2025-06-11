package nifcloud

import (
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/nifcloud/computing"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/nifcloud/dns"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/nifcloud/nas"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/nifcloud/network"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/nifcloud/rdb"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/nifcloud/sslcertificate"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) nifcloud.Nifcloud {
	return nifcloud.Nifcloud{
		Computing:      computing.Adapt(modules),
		DNS:            dns.Adapt(modules),
		NAS:            nas.Adapt(modules),
		Network:        network.Adapt(modules),
		RDB:            rdb.Adapt(modules),
		SSLCertificate: sslcertificate.Adapt(modules),
	}
}
