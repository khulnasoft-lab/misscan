package network

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/network"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptLoadBalancers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.LoadBalancer
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_load_balancer" "example" {
			    load_balancer_name = "example"
			    load_balancer_port = 80
			    ssl_policy_id      = "example-ssl-policy-id"
			}

			resource "nifcloud_load_balancer_listener" "example" {
			    load_balancer_name = nifcloud_load_balancer.example.load_balancer_name
			    load_balancer_port = 443
			    ssl_policy_name    = "example-ssl-policy-name"
			}

`,
			expected: []network.LoadBalancer{{
				Metadata: misscanTypes.NewTestMetadata(),
				Listeners: []network.LoadBalancerListener{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						TLSPolicy: misscanTypes.String("example-ssl-policy-id", misscanTypes.NewTestMetadata()),
						Protocol:  misscanTypes.String("HTTP", misscanTypes.NewTestMetadata()),
					},
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						TLSPolicy: misscanTypes.String("example-ssl-policy-name", misscanTypes.NewTestMetadata()),
						Protocol:  misscanTypes.String("HTTPS", misscanTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_load_balancer" "example" {
			}
`,

			expected: []network.LoadBalancer{{
				Metadata: misscanTypes.NewTestMetadata(),
				Listeners: []network.LoadBalancerListener{{
					Metadata: misscanTypes.NewTestMetadata(),
				}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLoadBalancers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
