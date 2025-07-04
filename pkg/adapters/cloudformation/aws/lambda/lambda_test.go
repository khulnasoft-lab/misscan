package lambda

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloudformation/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/lambda"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected lambda.Lambda
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  lambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      TracingConfig:
        Mode: Active
  permission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref lambdaFunction
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com
      SourceArn: arn
`,
			expected: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Tracing: lambda.Tracing{
							Mode: types.StringTest("Active"),
						},
						Permissions: []lambda.Permission{
							{
								Principal: types.StringTest("s3.amazonaws.com"),
								SourceARN: types.StringTest("arn"),
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
  lambdaFunction:
    Type: AWS::Lambda::Function
  permission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref lambdaFunction
  `,
			expected: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Permissions: []lambda.Permission{{}},
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
