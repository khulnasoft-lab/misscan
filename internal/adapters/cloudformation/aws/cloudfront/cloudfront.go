package cloudfront

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudfront"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: getDistributions(cfFile),
	}
}
