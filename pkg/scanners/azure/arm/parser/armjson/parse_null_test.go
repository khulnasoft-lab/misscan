package armjson

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_Null(t *testing.T) {
	example := []byte(`null`)
	var output string
	ref := &output
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &ref, &metadata)
	require.NoError(t, err)
}
