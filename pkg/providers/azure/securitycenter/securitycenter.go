package securitycenter

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	Metadata                 misscanTypes.Metadata
	EnableAlertNotifications misscanTypes.BoolValue
	Phone                    misscanTypes.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	Metadata misscanTypes.Metadata
	Tier     misscanTypes.StringValue
}
