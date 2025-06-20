package cloudtrail

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a CloudTrail instance
func Adapt(cfFile parser.FileContext) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{
		Trails: getCloudTrails(cfFile),
	}
}
