package redshift

import (
	"fmt"
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/redshift"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.Redshift
	}{
		{
			name: "reference key id",
			terraform: `
			resource "aws_kms_key" "redshift" {
				enable_key_rotation = true
			}
			
			resource "aws_redshift_cluster" "example" {
			  cluster_identifier = "tf-redshift-cluster"
			  publicly_accessible = false
			  number_of_nodes = 1
			  allow_version_upgrade = false
			  port = 5440
			  encrypted          = true
			  kms_key_id         = aws_kms_key.redshift.key_id
			  cluster_subnet_group_name = "redshift_subnet"
			}

			resource "aws_redshift_security_group" "default" {
				name = "redshift-sg"
				description = "some description"
			}
`,
			expected: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata:            misscanTypes.NewTestMetadata(),
						ClusterIdentifier:   misscanTypes.String("tf-redshift-cluster", misscanTypes.NewTestMetadata()),
						PubliclyAccessible:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						NumberOfNodes:       misscanTypes.Int(1, misscanTypes.NewTestMetadata()),
						AllowVersionUpgrade: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						EndPoint: redshift.EndPoint{
							Metadata: misscanTypes.NewTestMetadata(),
							Port:     misscanTypes.Int(5440, misscanTypes.NewTestMetadata()),
						},
						Encryption: redshift.Encryption{
							Metadata: misscanTypes.NewTestMetadata(),
							Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							KMSKeyID: misscanTypes.String("aws_kms_key.redshift", misscanTypes.NewTestMetadata()),
						},
						SubnetGroupName: misscanTypes.String("redshift_subnet", misscanTypes.NewTestMetadata()),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    misscanTypes.NewTestMetadata(),
						Description: misscanTypes.String("some description", misscanTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			fmt.Println(adapted.SecurityGroups[0].Description.Value())
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.Cluster
	}{
		{
			name: "key as string",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			  cluster_identifier = "tf-redshift-cluster"
			  publicly_accessible = false
			  number_of_nodes = 1
			  allow_version_upgrade = false
			  port = 5440
			  encrypted          = true
			  kms_key_id         = "key-id"
			  cluster_subnet_group_name = "redshift_subnet"
			}
`,
			expected: redshift.Cluster{
				Metadata:            misscanTypes.NewTestMetadata(),
				ClusterIdentifier:   misscanTypes.String("tf-redshift-cluster", misscanTypes.NewTestMetadata()),
				PubliclyAccessible:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				NumberOfNodes:       misscanTypes.Int(1, misscanTypes.NewTestMetadata()),
				AllowVersionUpgrade: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				EndPoint: redshift.EndPoint{
					Metadata: misscanTypes.NewTestMetadata(),
					Port:     misscanTypes.Int(5440, misscanTypes.NewTestMetadata()),
				},
				Encryption: redshift.Encryption{
					Metadata: misscanTypes.NewTestMetadata(),
					Enabled:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					KMSKeyID: misscanTypes.String("key-id", misscanTypes.NewTestMetadata()),
				},
				SubnetGroupName: misscanTypes.String("redshift_subnet", misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			}
`,
			expected: redshift.Cluster{
				Metadata:            misscanTypes.NewTestMetadata(),
				ClusterIdentifier:   misscanTypes.String("", misscanTypes.NewTestMetadata()),
				PubliclyAccessible:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				NumberOfNodes:       misscanTypes.Int(1, misscanTypes.NewTestMetadata()),
				AllowVersionUpgrade: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
				EndPoint: redshift.EndPoint{
					Metadata: misscanTypes.NewTestMetadata(),
					Port:     misscanTypes.Int(5439, misscanTypes.NewTestMetadata()),
				},
				Encryption: redshift.Encryption{
					Metadata: misscanTypes.NewTestMetadata(),
					Enabled:  misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					KMSKeyID: misscanTypes.String("", misscanTypes.NewTestMetadata()),
				},
				SubnetGroupName: misscanTypes.String("", misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0], modules[0])
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSecurityGroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.SecurityGroup
	}{
		{
			name: "defaults",
			terraform: `
resource "" "example" {
}
`,
			expected: redshift.SecurityGroup{
				Metadata:    misscanTypes.NewTestMetadata(),
				Description: misscanTypes.String("Managed by Terraform", misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecurityGroup(modules.GetBlocks()[0])
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "redshift" {
		enable_key_rotation = true
	}
	
	resource "aws_redshift_cluster" "example" {
	  cluster_identifier = "tf-redshift-cluster"
	  encrypted          = true
	  kms_key_id         = aws_kms_key.redshift.key_id
	  cluster_subnet_group_name = "subnet name"
	}

	resource "aws_redshift_security_group" "default" {
		name = "redshift-sg"
		description = "some description"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.SecurityGroups, 1)
	cluster := adapted.Clusters[0]
	securityGroup := adapted.SecurityGroups[0]

	assert.Equal(t, 6, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 8, cluster.Encryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, cluster.Encryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 2, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.SubnetGroupName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.SubnetGroupName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 15, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, securityGroup.Description.GetMetadata().Range().GetEndLine())
}
