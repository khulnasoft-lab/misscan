package msk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/msk"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  msk.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_msk_cluster" "example" {
				cluster_name           = "example"

				encryption_info {
					encryption_in_transit {
						client_broker = "TLS"
						in_cluster = true
					}
					encryption_at_rest_kms_key_arn = "foo-bar-key"
				}
			  
				logging_info {
				  broker_logs {
					cloudwatch_logs {
					  enabled   = true
					  log_group = aws_cloudwatch_log_group.test.name
					}
					firehose {
					  enabled         = true
					  delivery_stream = aws_kinesis_firehose_delivery_stream.test_stream.name
					}
					s3 {
					  enabled = true
					  bucket  = aws_s3_bucket.bucket.id
					  prefix  = "logs/msk-"
					}
				  }
				}
			  }
`,
			expected: msk.Cluster{
				Metadata: misscanTypes.NewTestMetadata(),
				EncryptionInTransit: msk.EncryptionInTransit{
					Metadata:     misscanTypes.NewTestMetadata(),
					ClientBroker: misscanTypes.String("TLS", misscanTypes.NewTestMetadata()),
				},
				EncryptionAtRest: msk.EncryptionAtRest{
					Metadata:  misscanTypes.NewTestMetadata(),
					KMSKeyARN: misscanTypes.String("foo-bar-key", misscanTypes.NewTestMetadata()),
					Enabled:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				},
				Logging: msk.Logging{
					Metadata: misscanTypes.NewTestMetadata(),
					Broker: msk.BrokerLogging{
						Metadata: misscanTypes.NewTestMetadata(),
						S3: msk.S3Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						Cloudwatch: msk.CloudwatchLogging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						Firehose: msk.FirehoseLogging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_msk_cluster" "example" {
			  }
`,
			expected: msk.Cluster{
				Metadata: misscanTypes.NewTestMetadata(),
				EncryptionInTransit: msk.EncryptionInTransit{
					Metadata:     misscanTypes.NewTestMetadata(),
					ClientBroker: misscanTypes.String("TLS_PLAINTEXT", misscanTypes.NewTestMetadata()),
				},
				Logging: msk.Logging{
					Metadata: misscanTypes.NewTestMetadata(),
					Broker: msk.BrokerLogging{
						Metadata: misscanTypes.NewTestMetadata(),
						S3: msk.S3Logging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
						Cloudwatch: msk.CloudwatchLogging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
						Firehose: msk.FirehoseLogging{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_msk_cluster" "example" {
		cluster_name           = "example"

		encryption_info {
			encryption_in_transit {
				client_broker = "TLS"
				in_cluster = true
			}
			encryption_at_rest_kms_key_arn = "foo-bar-key"	
		}
	  
		logging_info {
		  broker_logs {
			cloudwatch_logs {
			  enabled   = true
			  log_group = aws_cloudwatch_log_group.test.name
			}
			firehose {
			  enabled         = true
			  delivery_stream = aws_kinesis_firehose_delivery_stream.test_stream.name
			}
			s3 {
			  enabled = true
			  bucket  = aws_s3_bucket.bucket.id
			  prefix  = "logs/msk-"
			}
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 30, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, cluster.EncryptionInTransit.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, cluster.EncryptionInTransit.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, cluster.EncryptionAtRest.Metadata.Range().GetStartLine())
	assert.Equal(t, 10, cluster.EncryptionAtRest.Metadata.Range().GetEndLine())

	assert.Equal(t, 13, cluster.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 29, cluster.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 14, cluster.Logging.Broker.Metadata.Range().GetStartLine())
	assert.Equal(t, 28, cluster.Logging.Broker.Metadata.Range().GetEndLine())

	assert.Equal(t, 15, cluster.Logging.Broker.Cloudwatch.Metadata.Range().GetStartLine())
	assert.Equal(t, 18, cluster.Logging.Broker.Cloudwatch.Metadata.Range().GetEndLine())

	assert.Equal(t, 16, cluster.Logging.Broker.Cloudwatch.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, cluster.Logging.Broker.Cloudwatch.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, cluster.Logging.Broker.Firehose.Metadata.Range().GetStartLine())
	assert.Equal(t, 22, cluster.Logging.Broker.Firehose.Metadata.Range().GetEndLine())

	assert.Equal(t, 20, cluster.Logging.Broker.Firehose.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, cluster.Logging.Broker.Firehose.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, cluster.Logging.Broker.S3.Metadata.Range().GetStartLine())
	assert.Equal(t, 27, cluster.Logging.Broker.S3.Metadata.Range().GetEndLine())

	assert.Equal(t, 24, cluster.Logging.Broker.S3.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, cluster.Logging.Broker.S3.Enabled.GetMetadata().Range().GetEndLine())
}
