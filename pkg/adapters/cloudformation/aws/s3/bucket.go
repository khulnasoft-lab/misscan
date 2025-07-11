package s3

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

var aclConvertRegex = regexp.MustCompile(`[A-Z][^A-Z]*`)

func getBuckets(cfFile parser.FileContext) []s3.Bucket {
	var buckets []s3.Bucket
	bucketResources := cfFile.GetResourcesByType("AWS::S3::Bucket")

	for _, r := range bucketResources {
		s3b := s3.Bucket{
			Metadata:          r.Metadata(),
			Name:              r.GetStringProperty("BucketName"),
			PublicAccessBlock: getPublicAccessBlock(r),
			Encryption:        getEncryption(r, cfFile),
			Versioning: s3.Versioning{
				Metadata:  r.Metadata(),
				Enabled:   hasVersioning(r),
				MFADelete: misscanTypes.BoolUnresolvable(r.Metadata()),
			},
			Logging:                       getLogging(r),
			ACL:                           convertAclValue(r.GetStringProperty("AccessControl", "private")),
			LifecycleConfiguration:        getLifecycle(r),
			AccelerateConfigurationStatus: r.GetStringProperty("AccelerateConfiguration.AccelerationStatus"),
			Website:                       getWebsite(r),
			BucketLocation:                misscanTypes.String("", r.Metadata()),
			Objects:                       nil,
			BucketPolicies:                getBucketPolicies(cfFile, r),
		}

		buckets = append(buckets, s3b)
	}

	slices.SortFunc(buckets, func(a, b s3.Bucket) int {
		return cmp.Compare(a.Name.Value(), b.Name.Value())
	})

	return buckets
}

func getPublicAccessBlock(r *parser.Resource) *s3.PublicAccessBlock {
	block := r.GetProperty("PublicAccessBlockConfiguration")
	if block.IsNil() {
		return nil
	}

	return &s3.PublicAccessBlock{
		Metadata:              block.Metadata(),
		BlockPublicACLs:       block.GetBoolProperty("BlockPublicAcls"),
		BlockPublicPolicy:     block.GetBoolProperty("BlockPublicPolicy"),
		IgnorePublicACLs:      block.GetBoolProperty("IgnorePublicAcls"),
		RestrictPublicBuckets: block.GetBoolProperty("RestrictPublicBuckets"),
	}
}

func convertAclValue(aclValue misscanTypes.StringValue) misscanTypes.StringValue {
	matches := aclConvertRegex.FindAllString(aclValue.Value(), -1)

	return misscanTypes.String(strings.ToLower(strings.Join(matches, "-")), aclValue.GetMetadata())
}

func getLogging(r *parser.Resource) s3.Logging {
	logging := s3.Logging{
		Metadata:     r.Metadata(),
		Enabled:      misscanTypes.BoolDefault(false, r.Metadata()),
		TargetBucket: misscanTypes.StringDefault("", r.Metadata()),
	}

	if config := r.GetProperty("LoggingConfiguration"); config.IsNotNil() {
		logging.TargetBucket = config.GetStringProperty("DestinationBucketName")
		if logging.TargetBucket.IsNotEmpty() || !logging.TargetBucket.GetMetadata().IsResolvable() {
			logging.Enabled = misscanTypes.Bool(true, config.Metadata())
		}
	}
	return logging
}

func hasVersioning(r *parser.Resource) misscanTypes.BoolValue {
	versioningProp := r.GetProperty("VersioningConfiguration.Status")

	if versioningProp.IsNil() {
		return misscanTypes.BoolDefault(false, r.Metadata())
	}

	versioningEnabled := versioningProp.EqualTo("Enabled")

	return misscanTypes.Bool(versioningEnabled, versioningProp.Metadata())
}

func getEncryption(r *parser.Resource, _ parser.FileContext) s3.Encryption {
	encryption := s3.Encryption{
		Metadata:  r.Metadata(),
		Enabled:   misscanTypes.BoolDefault(false, r.Metadata()),
		Algorithm: misscanTypes.StringDefault("", r.Metadata()),
		KMSKeyId:  misscanTypes.StringDefault("", r.Metadata()),
	}

	if encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration"); encryptProps.IsNotNil() {
		for _, rule := range encryptProps.AsList() {
			algo := rule.GetProperty("ServerSideEncryptionByDefault.SSEAlgorithm")
			if algo.IsString() {
				algoVal := algo.AsString()
				isValidAlgo := slices.Contains(s3types.ServerSideEncryption("").Values(), s3types.ServerSideEncryption(algoVal))
				encryption.Enabled = misscanTypes.Bool(isValidAlgo, algo.Metadata())
				encryption.Algorithm = algo.AsStringValue()
			}

			kmsKeyProp := rule.GetProperty("ServerSideEncryptionByDefault.KMSMasterKeyID")
			if !kmsKeyProp.IsEmpty() && kmsKeyProp.IsString() {
				encryption.KMSKeyId = kmsKeyProp.AsStringValue()
			}
		}
	}

	return encryption
}

func getLifecycle(resource *parser.Resource) []s3.Rules {
	RuleProp := resource.GetProperty("LifecycleConfiguration.Rules")

	var rule []s3.Rules

	if RuleProp.IsNil() || RuleProp.IsNotList() {
		return rule
	}

	for _, r := range RuleProp.AsList() {
		rule = append(rule, s3.Rules{
			Metadata: r.Metadata(),
			Status:   r.GetStringProperty("Status"),
		})
	}
	return rule
}

func getWebsite(r *parser.Resource) *s3.Website {
	block := r.GetProperty("WebsiteConfiguration")
	if block.IsNil() {
		return nil
	}
	return &s3.Website{
		Metadata: block.Metadata(),
	}
}

func getBucketPolicies(fctx parser.FileContext, r *parser.Resource) []iam.Policy {
	var policies []iam.Policy
	for _, bucketPolicy := range fctx.GetResourcesByType("AWS::S3::BucketPolicy") {
		bucket := bucketPolicy.GetStringProperty("Bucket")
		if bucket.NotEqualTo(r.GetStringProperty("BucketName").Value()) && bucket.NotEqualTo(r.ID()) {
			continue
		}

		doc := bucketPolicy.GetProperty("PolicyDocument")
		if doc.IsNil() {
			continue
		}

		parsed, err := iamgo.Parse(doc.GetJsonBytes())
		if err != nil {
			continue
		}
		policies = append(policies, iam.Policy{
			Metadata: doc.Metadata(),
			Name:     misscanTypes.StringDefault("", doc.Metadata()),
			Document: iam.Document{
				Metadata: doc.Metadata(),
				Parsed:   *parsed,
			},
			Builtin: misscanTypes.Bool(false, doc.Metadata()),
		})
	}

	return policies
}
