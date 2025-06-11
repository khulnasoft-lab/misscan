package cloudwatch

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type CloudWatch struct {
	LogGroups []LogGroup
	Alarms    []Alarm
}

type Alarm struct {
	Metadata   misscanTypes.Metadata
	AlarmName  misscanTypes.StringValue
	MetricName misscanTypes.StringValue
	Dimensions []AlarmDimension
	Metrics    []MetricDataQuery
}

type AlarmDimension struct {
	Metadata misscanTypes.Metadata
	Name     misscanTypes.StringValue
	Value    misscanTypes.StringValue
}

type MetricFilter struct {
	Metadata      misscanTypes.Metadata
	FilterName    misscanTypes.StringValue
	FilterPattern misscanTypes.StringValue
}

type MetricDataQuery struct {
	Metadata   misscanTypes.Metadata
	Expression misscanTypes.StringValue
	ID         misscanTypes.StringValue
}

type LogGroup struct {
	Metadata        misscanTypes.Metadata
	Arn             misscanTypes.StringValue
	Name            misscanTypes.StringValue
	KMSKeyID        misscanTypes.StringValue
	RetentionInDays misscanTypes.IntValue
	MetricFilters   []MetricFilter
}
