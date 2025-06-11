package network

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptElasticLoadBalancers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.ElasticLoadBalancer
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_elb" "example" {
                protocol = "HTTP"

				network_interface  {
					network_id     = "net-COMMON_PRIVATE"
					is_vip_network = false
				}
			}

            resource "nifcloud_elb_listener" "example" {
                elb_id   = nifcloud_elb.example.id
                protocol = "HTTPS"
            }
`,
			expected: []network.ElasticLoadBalancer{{
				Metadata: misscanTypes.NewTestMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     misscanTypes.NewTestMetadata(),
						NetworkID:    misscanTypes.String("net-COMMON_PRIVATE", misscanTypes.NewTestMetadata()),
						IsVipNetwork: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Protocol: misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
					},
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Protocol: misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_elb" "example" {
				network_interface  {
				}
			}
`,

			expected: []network.ElasticLoadBalancer{{
				Metadata: misscanTypes.NewTestMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     misscanTypes.NewTestMetadata(),
						NetworkID:    misscanTypes.String("", misscanTypes.NewTestMetadata()),
						IsVipNetwork: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{{
					Metadata: misscanTypes.NewTestMetadata(),
				}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptElasticLoadBalancers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
