package ec2

import (
	"testing"

	aws2 "github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws/test"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	vpcApi "github.com/aws/aws-sdk-go-v2/service/ec2"
	vpcTypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

type rule struct {
	egress     bool
	protocol   string
	ruleAction vpcTypes.RuleAction
	cidrBlock  string
	fromPort   int
	toPort     int
}

type nacl struct {
	naclRules []rule
}

type sg struct {
	name        string
	description string
	sgRules     []rule
}

type vpcDetails struct {
	nacl            *nacl
	securityGroup   *sg
	flowLogsEnabled bool
}

func Test_VPCNetworkACLs(t *testing.T) {

	tests := []struct {
		name    string
		details vpcDetails
	}{
		{
			name: "simple nacl",
			details: vpcDetails{
				nacl: &nacl{
					naclRules: []rule{
						{
							egress:     true,
							protocol:   "tcp",
							cidrBlock:  "10.0.0.0/24",
							ruleAction: vpcTypes.RuleActionDeny,
							fromPort:   80,
							toPort:     80,
						},
					},
				},
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapVPC(t, ra, tt.details)

			testState := &state.State{}
			adapter := &adapter{}
			err = adapter.Adapt(ra, testState)
			require.NoError(t, err)

			require.NotNil(t, testState.AWS.EC2)
			require.Len(t, testState.AWS.EC2.NetworkACLs, 3)

			var aclFound bool

			for _, a := range testState.AWS.EC2.NetworkACLs {
				if !a.IsDefaultRule.Value() {
					aclFound = true
					break
				}
			}

			require.True(t, aclFound)

		})
	}
}

func Test_VPCFlowLogs(t *testing.T) {

	tests := []struct {
		name    string
		details vpcDetails
	}{
		{
			name: "simple flow logs",
			details: vpcDetails{
				flowLogsEnabled: true,
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpcId := bootstrapVPC(t, ra, tt.details)

			testState := &state.State{}
			adapter := &adapter{}
			err = adapter.Adapt(ra, testState)
			require.NoError(t, err)

			require.NotNil(t, testState.AWS.EC2)
			var testVPCs []ec2.VPC
			for _, v := range testState.AWS.EC2.VPCs {
				if v.IsDefault.IsFalse() {
					testVPCs = append(testVPCs, v)
				}
			}

			require.Len(t, testVPCs, 1)
			vpc := testVPCs[0]
			require.Equal(t, tt.details.flowLogsEnabled, vpc.FlowLogsEnabled.Value())

			destroyVPC(t, ra, vpcId)

		})
	}
}

func Test_VPCSecurityGroups(t *testing.T) {

	tests := []struct {
		name    string
		details vpcDetails
	}{
		{
			name: "simple security group",
			details: vpcDetails{
				securityGroup: &sg{
					name:        "test-sg",
					description: "a test security group description",
					sgRules: []rule{
						{
							egress:    true,
							protocol:  "tcp",
							cidrBlock: "10.0.0.0/24",
							fromPort:  80,
							toPort:    80,
						},
					},
				},
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpcId := bootstrapVPC(t, ra, tt.details)

			testState := &state.State{}
			adapter := &adapter{}
			err = adapter.Adapt(ra, testState)
			require.NoError(t, err)

			require.NotNil(t, testState.AWS.EC2)
			require.Len(t, testState.AWS.EC2.SecurityGroups, 3)

			sg := testState.AWS.EC2.SecurityGroups[0]
			require.NotNil(t, sg)

			destroyVPC(t, ra, vpcId)

		})
	}
}

func destroyVPC(t *testing.T, ra *aws2.RootAdapter, id *string) {
	api := vpcApi.NewFromConfig(ra.SessionConfig())

	_, err := api.DeleteVpc(ra.Context(), &vpcApi.DeleteVpcInput{
		VpcId: id,
	})

	require.NoError(t, err)
}

func bootstrapVPC(t *testing.T, ra *aws2.RootAdapter, spec vpcDetails) *string {

	api := vpcApi.NewFromConfig(ra.SessionConfig())

	vpc, err := api.CreateVpc(ra.Context(), &vpcApi.CreateVpcInput{
		CidrBlock: aws.String("10.0.0.0/16"),
	})

	require.NoError(t, err)

	if spec.nacl != nil {
		addNacl(t, ra, spec, api, vpc)
	}

	if spec.securityGroup != nil {
		addSecurityGroup(t, ra, spec, api, vpc)
	}

	if spec.flowLogsEnabled {
		addFlowLogs(t, ra, api, vpc)
	}

	return vpc.Vpc.VpcId
}

func addFlowLogs(t *testing.T, ra *aws2.RootAdapter, api *vpcApi.Client, vpc *vpcApi.CreateVpcOutput) {
	logs, err := api.CreateFlowLogs(ra.Context(), &vpcApi.CreateFlowLogsInput{
		ResourceIds:        []string{*vpc.Vpc.VpcId},
		ResourceType:       vpcTypes.FlowLogsResourceTypeVpc,
		LogDestinationType: vpcTypes.LogDestinationTypeS3,
		LogDestination:     aws.String("arn:aws:s3:::access-logs"),
	})

	require.NoError(t, err)
	require.NotNil(t, logs)
}

func addNacl(t *testing.T, ra *aws2.RootAdapter, spec vpcDetails, api *vpcApi.Client, vpc *vpcApi.CreateVpcOutput) {
	acl, err := api.CreateNetworkAcl(ra.Context(), &vpcApi.CreateNetworkAclInput{
		VpcId: vpc.Vpc.VpcId,
	})
	require.NoError(t, err)

	for i, rule := range spec.nacl.naclRules {
		_, err = api.CreateNetworkAclEntry(ra.Context(), &vpcApi.CreateNetworkAclEntryInput{
			NetworkAclId: acl.NetworkAcl.NetworkAclId,
			Egress:       aws.Bool(rule.egress),
			RuleAction:   rule.ruleAction,
			RuleNumber:   aws.Int32(int32(i)),
			Protocol:     aws.String(rule.protocol),
			CidrBlock:    aws.String(rule.cidrBlock),
			PortRange: &vpcTypes.PortRange{
				From: aws.Int32(80),
				To:   aws.Int32(80),
			},
		})
		require.NoError(t, err)
	}
}

func addSecurityGroup(t *testing.T, ra *aws2.RootAdapter, spec vpcDetails, api *vpcApi.Client, vpc *vpcApi.CreateVpcOutput) {
	_, err := api.CreateSecurityGroup(ra.Context(), &vpcApi.CreateSecurityGroupInput{
		VpcId:       vpc.Vpc.VpcId,
		GroupName:   aws.String(spec.securityGroup.name),
		Description: aws.String(spec.securityGroup.description),
	})
	require.NoError(t, err)
}
