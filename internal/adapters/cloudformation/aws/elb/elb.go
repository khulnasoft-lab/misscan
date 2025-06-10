package elb

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) elb.ELB {
	return elb.ELB{
		LoadBalancers: getLoadBalancers(cfFile),
	}
}
