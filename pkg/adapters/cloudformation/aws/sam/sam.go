package sam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an SAM instance
func Adapt(cfFile parser.FileContext) sam.SAM {
	return sam.SAM{
		APIs:          getApis(cfFile),
		HttpAPIs:      getHttpApis(cfFile),
		Functions:     getFunctions(cfFile),
		StateMachines: getStateMachines(cfFile),
		SimpleTables:  getSimpleTables(cfFile),
	}
}
