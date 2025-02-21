package sslcertificate

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ServerCertificate struct {
	Metadata   misscanTypes.Metadata
	Expiration misscanTypes.TimeValue
}
