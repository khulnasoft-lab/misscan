package kinesis

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kinesis"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a Kinesis instance
func Adapt(cfFile parser.FileContext) kinesis.Kinesis {
	return kinesis.Kinesis{
		Streams: getStreams(cfFile),
	}
}
