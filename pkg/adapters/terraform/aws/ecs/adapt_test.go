package ecs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecs"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptClusterSettings(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecs.ClusterSettings
	}{
		{
			name: "container insights enabled",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"

				setting {
				  name  = "containerInsights"
				  value = "enabled"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 misscanTypes.NewTestMetadata(),
				ContainerInsightsEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "container insights enhanced",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"

				setting {
				  name  = "containerInsights"
				  value = "enhanced"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 misscanTypes.NewTestMetadata(),
				ContainerInsightsEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "invalid name",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"

				setting {
				  name  = "invalidName"
				  value = "enabled"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 misscanTypes.NewTestMetadata(),
				ContainerInsightsEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_cluster" "example" {
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 misscanTypes.NewTestMetadata(),
				ContainerInsightsEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptClusterSettings(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTaskDefinitionResource(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecs.TaskDefinition
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_ecs_task_definition" "example" {
				family                = "service"
				container_definitions = <<EOF
[
	{
	"name": "my_service",
	"image": "my_image",
	"essential": true,
	"memory": "256",
	"cpu": "2",
	"environment": [
		{ "name": "ENVIRONMENT", "value": "development" }
	]
	}
]
				EOF

				volume {
				  name = "service-storage"

				  efs_volume_configuration {
					transit_encryption      = "ENABLED"
				  }
				}
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: misscanTypes.NewTestMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
							Metadata:                 misscanTypes.NewTestMetadata(),
							TransitEncryptionEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
				ContainerDefinitions: []ecs.ContainerDefinition{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						Name:       misscanTypes.String("my_service", misscanTypes.NewTestMetadata()),
						Image:      misscanTypes.String("my_image", misscanTypes.NewTestMetadata()),
						CPU:        misscanTypes.String("2", misscanTypes.NewTestMetadata()),
						Memory:     misscanTypes.String("256", misscanTypes.NewTestMetadata()),
						Essential:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						Privileged: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						Environment: []ecs.EnvVar{
							{
								Name:  misscanTypes.StringTest("ENVIRONMENT"),
								Value: misscanTypes.StringTest("development"),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_task_definition" "example" {
				volume {
					name = "service-storage"

					efs_volume_configuration {
					}
				  }
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: misscanTypes.NewTestMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{

							Metadata:                 misscanTypes.NewTestMetadata(),
							TransitEncryptionEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
				ContainerDefinitions: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTaskDefinitionResource(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_ecs_cluster" "example" {
		name = "services-cluster"

		setting {
		  name  = "containerInsights"
		  value = "enabled"
		}
	}

	resource "aws_ecs_task_definition" "example" {
		family                = "service"
		container_definitions = <<EOF
	[
		{
			"name": "my_service",
			"essential": true,
			"memory": 256,
			"environment": [
				{ "name": "ENVIRONMENT", "value": "development" }
			]
		}
	]
		EOF

		volume {
		  name = "service-storage"

		  efs_volume_configuration {
			transit_encryption      = "ENABLED"
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.TaskDefinitions, 1)

	cluster := adapted.Clusters[0]
	taskDefinition := adapted.TaskDefinitions[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 5, cluster.Settings.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, cluster.Settings.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, taskDefinition.Metadata.Range().GetStartLine())
	assert.Equal(t, 33, taskDefinition.Metadata.Range().GetEndLine())

	assert.Equal(t, 26, taskDefinition.Volumes[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 32, taskDefinition.Volumes[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 29, taskDefinition.Volumes[0].EFSVolumeConfiguration.Metadata.Range().GetStartLine())
	assert.Equal(t, 31, taskDefinition.Volumes[0].EFSVolumeConfiguration.Metadata.Range().GetEndLine())

	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetEndLine())
}
