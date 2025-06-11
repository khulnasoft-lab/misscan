package kms

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	Metadata        misscanTypes.Metadata
	Usage           misscanTypes.StringValue
	RotationEnabled misscanTypes.BoolValue
}
