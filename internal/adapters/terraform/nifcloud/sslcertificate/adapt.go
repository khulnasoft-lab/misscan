package sslcertificate

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/sslcertificate"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) sslcertificate.SSLCertificate {
	return sslcertificate.SSLCertificate{
		ServerCertificates: adaptServerCertificates(modules),
	}
}
