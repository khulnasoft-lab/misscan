package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_AdaptAutoscaling(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "basic config",
			terraform: `
			resource "aws_launch_configuration" "my_config" {
				associate_public_ip_address = false
				name             = "web_config"
				image_id         = data.aws_ami.ubuntu.id
				instance_type    = "t2.micro"
				user_data_base64 = "ZXhwb3J0IEVESVRPUj12aW1hY3M="

				root_block_device {
					encrypted = true
				}
				ebs_block_device {
					encrypted = true
				}
			}
			`,
			expected: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          misscanTypes.NewTestMetadata(),
						Name:              misscanTypes.String("web_config", misscanTypes.NewTestMetadata()),
						AssociatePublicIP: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						UserData:          misscanTypes.String("export EDITOR=vimacs", misscanTypes.NewTestMetadata()),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     misscanTypes.NewTestMetadata(),
							HttpTokens:   misscanTypes.String("", misscanTypes.NewTestMetadata()),
							HttpEndpoint: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  misscanTypes.NewTestMetadata(),
							Encrypted: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  misscanTypes.NewTestMetadata(),
								Encrypted: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
		{
			name: "user data overrides user data base 64",
			terraform: `
			resource "aws_launch_configuration" "my_config" {
				associate_public_ip_address = false
				name             = "web_config"
				image_id         = data.aws_ami.ubuntu.id
				instance_type    = "t2.micro"
				user_data_base64 = "ZXhwb3J0IEVESVRPUj12aW1hY3M="

				user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
			   EOF

				root_block_device {
					encrypted = true
				}
			}
`,
			expected: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          misscanTypes.NewTestMetadata(),
						Name:              misscanTypes.String("web_config", misscanTypes.NewTestMetadata()),
						AssociatePublicIP: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						UserData: misscanTypes.String(`export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
`, misscanTypes.NewTestMetadata()),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     misscanTypes.NewTestMetadata(),
							HttpTokens:   misscanTypes.String("", misscanTypes.NewTestMetadata()),
							HttpEndpoint: misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  misscanTypes.NewTestMetadata(),
							Encrypted: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "https token enforced",
			terraform: `
			resource "aws_launch_template" "my_tmpl" {
				associate_public_ip_address = false
				name             = "my_template"
				image_id         = data.aws_ami.ubuntu.id
				instance_type    = "t2.micro"

				metadata_options {
					http_tokens = "required"
				}
			}
			`,
			expected: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: misscanTypes.NewTestMetadata(),
							UserData: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							MetadataOptions: ec2.MetadataOptions{
								Metadata:     misscanTypes.NewTestMetadata(),
								HttpTokens:   misscanTypes.String("required", misscanTypes.NewTestMetadata()),
								HttpEndpoint: misscanTypes.String("", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestAutoscalingLines(t *testing.T) {
	src := `
	resource "aws_launch_configuration" "my_config" {
		associate_public_ip_address = false
		name             = "web_config"
		image_id         = data.aws_ami.ubuntu.id
		instance_type    = "t2.micro"

		user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
	   EOF

		root_block_device {
			encrypted = true
		}
		metadata_options {
			http_tokens = "required"
		}
		ebs_block_device {
			encrypted = true
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.LaunchConfigurations, 1)
	launchConfig := adapted.LaunchConfigurations[0]

	assert.Equal(t, 3, launchConfig.AssociatePublicIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, launchConfig.AssociatePublicIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, launchConfig.UserData.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, launchConfig.UserData.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, launchConfig.RootBlockDevice.Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, launchConfig.RootBlockDevice.Encrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, launchConfig.MetadataOptions.HttpTokens.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, launchConfig.MetadataOptions.HttpTokens.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, launchConfig.EBSBlockDevices[0].Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, launchConfig.EBSBlockDevices[0].Encrypted.GetMetadata().Range().GetEndLine())

}
