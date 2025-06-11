package documentdb

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

// Adapt adaps a documentDB instance
func Adapt(cfFile parser.FileContext) documentdb.DocumentDB {
	return documentdb.DocumentDB{
		Clusters: getClusters(cfFile),
	}
}
