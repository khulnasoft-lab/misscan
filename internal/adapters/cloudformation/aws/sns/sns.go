package sns

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sns"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) sns.SNS {
	return sns.SNS{
		Topics: getTopics(cfFile),
	}
}
