package athena

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloudformation/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/athena"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected athena.Athena
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyAthenaWorkGroup:
    Type: AWS::Athena::WorkGroup
    Properties:
      Name: MyCustomWorkGroup
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        ResultConfiguration:
          EncryptionOption: SSE_KMS
`,
			expected: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Name:                 types.StringTest("MyCustomWorkGroup"),
						EnforceConfiguration: types.BoolTest(true),
						Encryption: athena.EncryptionConfiguration{
							Type: types.StringTest("SSE_KMS"),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyAthenaWorkGroup:
    Type: AWS::Athena::WorkGroup
`,
			expected: athena.Athena{
				Workgroups: []athena.Workgroup{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
