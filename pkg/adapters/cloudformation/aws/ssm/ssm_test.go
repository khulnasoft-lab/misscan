package ssm

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloudformation/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ssm"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ssm.SSM
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MySecretA:
    Type: 'AWS::SecretsManager::Secret'
    Properties:
      Name: MySecretForAppA
      KmsKeyId: alias/exampleAlias
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						KMSKeyID: types.StringTest("alias/exampleAlias"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MySecretA:
    Type: 'AWS::SecretsManager::Secret'
  `,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
