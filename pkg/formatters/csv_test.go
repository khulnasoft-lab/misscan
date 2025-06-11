package formatters

import (
	"bytes"
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/dynamodb"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_CSV(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: misscanTypes.NewTestMetadata(),
			Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
		})
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}

func Test_CSV_WithoutPassed(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: misscanTypes.NewTestMetadata(),
			Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
		})
	results.AddPassed(misscanTypes.NewTestMetadata(), "Everything is fine.")
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}

func Test_CSV_WithPassed(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Everything is fine.,,true
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).WithIncludePassed(true).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: misscanTypes.NewTestMetadata(),
			Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
		})
	results.AddPassed(misscanTypes.NewTestMetadata(), "Everything is fine.")
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}
