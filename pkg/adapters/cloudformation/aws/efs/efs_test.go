package efs

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloudformation/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/efs"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected efs.EFS
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  FileSystemResource:
    Type: 'AWS::EFS::FileSystem'
    Properties:
      Encrypted: true
`,
			expected: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Encrypted: types.BoolTest(true),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  FileSystemResource:
    Type: 'AWS::EFS::FileSystem'
  `,
			expected: efs.EFS{
				FileSystems: []efs.FileSystem{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
