package cloudwatch

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudwatch"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

func getLogGroups(ctx parser.FileContext) (logGroups []cloudwatch.LogGroup) {

	logGroupResources := ctx.GetResourcesByType("AWS::Logs::LogGroup")

	for _, r := range logGroupResources {
		group := cloudwatch.LogGroup{
			Metadata:        r.Metadata(),
			Name:            r.GetStringProperty("LogGroupName"),
			KMSKeyID:        r.GetStringProperty("KmsKeyId"),
			RetentionInDays: r.GetIntProperty("RetentionInDays"),
		}
		logGroups = append(logGroups, group)
	}

	return logGroups
}
