package documentdb

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloudformation/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected documentdb.DocumentDB
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDBCluster:
    Type: 'AWS::DocDB::DBCluster'
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: sample-cluster
      KmsKeyId: your-kms-key-id
      StorageEncrypted: true
      EnableCloudwatchLogsExports:
        - audit
        - general
  myDBInstance:
    Type: 'AWS::DocDB::DBInstance'
    Properties:
      DBClusterIdentifier: sample-cluster
      KmsKeyId: your-kms-key-id
`,
			expected: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Identifier:            types.StringTest("sample-cluster"),
						BackupRetentionPeriod: types.IntTest(8),
						KMSKeyID:              types.StringTest("your-kms-key-id"),
						StorageEncrypted:      types.BoolTest(true),
						EnabledLogExports: []types.StringValue{
							types.StringTest("audit"),
							types.StringTest("general"),
						},
						Instances: []documentdb.Instance{
							{
								KMSKeyID: types.StringTest("your-kms-key-id"),
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  myDBCluster:
    Type: 'AWS::DocDB::DBCluster'
  `,
			expected: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						BackupRetentionPeriod: types.IntTest(1),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
