package nifcloud

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/computing"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/dns"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/nas"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/sslcertificate"
)

type Nifcloud struct {
	Computing      computing.Computing
	DNS            dns.DNS
	NAS            nas.NAS
	Network        network.Network
	RDB            rdb.RDB
	SSLCertificate sslcertificate.SSLCertificate
}
