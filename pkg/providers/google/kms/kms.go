package kms

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	Metadata misscanTypes.Metadata
	Keys     []Key
}

type Key struct {
	Metadata              misscanTypes.Metadata
	RotationPeriodSeconds misscanTypes.IntValue
}
