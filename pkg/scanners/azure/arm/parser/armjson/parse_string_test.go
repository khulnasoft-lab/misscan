package armjson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_String(t *testing.T) {
	example := []byte(`"hello"`)
	var output string
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.Equal(t, "hello", output)
}

func Test_StringToUninitialisedPointer(t *testing.T) {
	example := []byte(`"hello"`)
	var str *string
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, str, &metadata)
	require.Error(t, err)
	assert.Nil(t, str)
}

func Test_String_ToInterface(t *testing.T) {
	example := []byte(`"hello"`)
	var output any
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.Equal(t, "hello", output)
}
