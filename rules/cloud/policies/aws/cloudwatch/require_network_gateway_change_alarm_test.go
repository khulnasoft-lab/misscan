package cloudwatch

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudwatch"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNetworkGatewayChangeAlarm(t *testing.T) {
	tests := []struct {
		name       string
		cloudtrail cloudtrail.CloudTrail
		cloudwatch cloudwatch.CloudWatch
		expected   bool
	}{
		{
			name: "Multi-region CloudTrail alarms on network gateway changes",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  misscanTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: misscanTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", misscanTypes.NewTestMetadata()),
						IsLogging:                 misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						IsMultiRegion:             misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						Arn:      misscanTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", misscanTypes.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{
							{
								Metadata:   misscanTypes.NewTestMetadata(),
								FilterName: misscanTypes.String("NetworkGatewayChange", misscanTypes.NewTestMetadata()),
								FilterPattern: misscanTypes.String(`{($.eventName=CreateCustomerGateway) || 
					($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || 
					($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || 
					($.eventName=DetachInternetGateway)}`, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:   misscanTypes.NewTestMetadata(),
						AlarmName:  misscanTypes.String("NetworkGatewayChange", misscanTypes.NewTestMetadata()),
						MetricName: misscanTypes.String("NetworkGatewayChange", misscanTypes.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								ID:       misscanTypes.String("NetworkGatewayChange", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for network gateway changes",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  misscanTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: misscanTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", misscanTypes.NewTestMetadata()),
						IsLogging:                 misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						IsMultiRegion:             misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata:      misscanTypes.NewTestMetadata(),
						Arn:           misscanTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", misscanTypes.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:  misscanTypes.NewTestMetadata(),
						AlarmName: misscanTypes.String("NetworkGatewayChange", misscanTypes.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudWatch = test.cloudwatch
			testState.AWS.CloudTrail = test.cloudtrail
			results := requireNetworkGatewayChangeAlarm.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == requireNetworkGatewayChangeAlarm.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
