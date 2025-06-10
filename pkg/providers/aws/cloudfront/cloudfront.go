package cloudfront

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	Metadata               misscanTypes.Metadata
	WAFID                  misscanTypes.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	Metadata misscanTypes.Metadata
	Bucket   misscanTypes.StringValue
}

type CacheBehaviour struct {
	Metadata             misscanTypes.Metadata
	ViewerProtocolPolicy misscanTypes.StringValue
}

const (
	ViewerPolicyProtocolAllowAll        = "allow-all"
	ViewerPolicyProtocolHTTPSOnly       = "https-only"
	ViewerPolicyProtocolRedirectToHTTPS = "redirect-to-https"
)

const (
	ProtocolVersionTLS1_2 = "TLSv1.2_2021"
)

type ViewerCertificate struct {
	Metadata               misscanTypes.Metadata
	MinimumProtocolVersion misscanTypes.StringValue
}
