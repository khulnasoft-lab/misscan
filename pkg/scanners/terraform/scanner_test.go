package terraform

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/rego"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/options"
)

func Test_OptionWithPolicyDirs(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
		"/code/main.tf":    `resource "aws_s3_bucket" "my-bucket" {}`,
		"/rules/test.rego": emptyBucketCheck,
	})

	results, err := scanFS(fsys, "code",
		rego.WithPolicyFilesystem(fsys),
		rego.WithPolicyDirs("rules"),
		rego.WithPolicyNamespaces("user"),
	)
	require.NoError(t, err)
	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]
	assert.Equal(t, "USER-TEST-0123", failure.Rule().AVDID)

	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     1,
			Content:    "resource \"aws_s3_bucket\" \"my-bucket\" {}",
			IsCause:    true,
			FirstCause: true,
			LastCause:  true,
		},
	}, actualCode.Lines)

}

func Test_OptionWithPolicyNamespaces(t *testing.T) {

	tests := []struct {
		includedNamespaces []string
		policyNamespace    string
		wantFailure        bool
	}{
		{
			includedNamespaces: nil,
			policyNamespace:    "blah",
			wantFailure:        false,
		},
		{
			includedNamespaces: nil,
			policyNamespace:    "appshield.something",
			wantFailure:        true,
		},
		{
			includedNamespaces: nil,
			policyNamespace:    "defsec.blah",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{"user"},
			policyNamespace:    "users",
			wantFailure:        false,
		},
		{
			includedNamespaces: []string{"users"},
			policyNamespace:    "something.users",
			wantFailure:        false,
		},
		{
			includedNamespaces: []string{"users"},
			policyNamespace:    "users",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{"users"},
			policyNamespace:    "users.my_rule",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{
				"a",
				"users",
				"b",
			},
			policyNamespace: "users",
			wantFailure:     true,
		},
		{
			includedNamespaces: []string{"user"},
			policyNamespace:    "defsec",
			wantFailure:        true,
		},
	}

	for i, test := range tests {

		t.Run(strconv.Itoa(i), func(t *testing.T) {

			fs := testutil.CreateFS(t, map[string]string{
				"/code/main.tf": `
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`,
				"/rules/test.rego": fmt.Sprintf(`
# METADATA
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#       - service: s3
#         provider: aws
package %s

deny[cause] {
bucket := input.aws.s3.buckets[_]
bucket.name.value == "evil"
cause := bucket.name
}

				`, test.policyNamespace),
			})

			scanner := New(
				rego.WithPolicyDirs("rules"),
				rego.WithPolicyNamespaces(test.includedNamespaces...),
			)

			results, err := scanner.ScanFS(t.Context(), fs, "code")
			require.NoError(t, err)

			var found bool
			for _, result := range results.GetFailed() {
				if result.RegoNamespace() == test.policyNamespace && result.RegoRule() == "deny" {
					found = true
					break
				}
			}
			assert.Equal(t, test.wantFailure, found)
		})
	}

}

func Test_IAMPolicyRego(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_sqs_queue_policy" "bad_example" {
   queue_url = aws_sqs_queue.q.id

   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "*"
     }
   ]
 }
 POLICY
 }`,
		"/rules/test.rego": `
# METADATA
# title: SQS policies should not allow wildcard actions
# description: SQS queue policies should avoid using "*" for actions, as this allows overly permissive access.
# scope: package
# schemas:
#  - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-using-identity-based-policies.html
# custom:
#   id: TEST123
#   avd_id: AVD-TEST-0123
#   short_code: no-wildcard-actions
#   severity: CRITICAL
#   recommended_action: Avoid using "*" for actions in SQS policies and specify only required actions.
#   input:
#     selector:
#     - type: cloud
#       subtypes: 
#         - service: sqs
#           provider: aws
package defsec.abcdefg


deny[res] {
	queue := input.aws.sqs.queues[_]
	policy := queue.policies[_]
	doc := json.unmarshal(policy.document.value)
	statement = doc.Statement[_]
	action := statement.Action[_]
	action == "*"
	res := result.new("SQS Policy contains wildcard in action", policy.document)
}
`,
	})

	scanner := New(
		rego.WithPolicyDirs("rules"),
		rego.WithEmbeddedLibraries(true),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Equal(t, "AVD-TEST-0123", results[0].Rule().AVDID)
	assert.NotNil(t, results[0].Metadata().Range().GetFS())

}

func Test_ContainerDefinitionRego(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_ecs_task_definition" "test" {
  family                = "test"
  container_definitions = <<TASK_DEFINITION
[
  {
	"privileged": true,
    "cpu": "10",
    "command": ["sleep", "10"],
    "entryPoint": ["/"],
    "environment": [
      {"name": "VARNAME", "value": "VARVAL"}
    ],
    "essential": true,
    "image": "jenkins",
    "memory": "128",
    "name": "jenkins",
    "portMappings": [
      {
        "containerPort": 80,
        "hostPort": 8080
      }
    ],
        "resourceRequirements":[
            {
                "type":"InferenceAccelerator",
                "value":"device_1"
            }
        ]
  }
]
TASK_DEFINITION

  inference_accelerator {
    device_name = "device_1"
    device_type = "eia1.medium"
  }
}`,
		"/rules/test.rego": `
package defsec.abcdefg


__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec", "subtypes": [{"service": "ecs", "provider": "aws"}]}],
}

deny[res] {
	definition := input.aws.ecs.taskdefinitions[_].containerdefinitions[_]
	definition.privileged.value == true
	res := result.new("Privileged container detected", definition.privileged)
}
`,
	})

	scanner := New(
		rego.WithPolicyDirs("rules"),
		rego.WithEmbeddedLibraries(true),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Equal(t, "AVD-TEST-0123", results[0].Rule().AVDID)
	assert.NotNil(t, results[0].Metadata().Range().GetFS())

}

func Test_S3_Linking(t *testing.T) {

	code := `
## tfsec:ignore:aws-s3-enable-bucket-encryption
## tfsec:ignore:aws-s3-enable-bucket-logging
## tfsec:ignore:aws-s3-enable-versioning
resource "aws_s3_bucket" "blubb" {
  bucket = "test"
}

resource "aws_s3_bucket_public_access_block" "audit_logs_athena" {
  bucket = aws_s3_bucket.blubb.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# tfsec:ignore:aws-s3-enable-bucket-encryption
# tfsec:ignore:aws-s3-enable-bucket-logging
# tfsec:ignore:aws-s3-enable-versioning
resource "aws_s3_bucket" "foo" {
  bucket        = "prefix-" # remove this variable and it works; does not report
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "foo" {
  bucket = aws_s3_bucket.foo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

`

	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": code,
	})

	scanner := New()

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	failed := results.GetFailed()
	for _, result := range failed {
		// public access block
		assert.NotEqual(t, "AVD-AWS-0094", result.Rule().AVDID, "AVD-AWS-0094 should not be reported - was found at "+result.Metadata().Range().String())
		// encryption
		assert.NotEqual(t, "AVD-AWS-0088", result.Rule().AVDID)
		// logging
		assert.NotEqual(t, "AVD-AWS-0089", result.Rule().AVDID)
		// versioning
		assert.NotEqual(t, "AVD-AWS-0090", result.Rule().AVDID)
	}
}

func Test_S3_Linking_PublicAccess(t *testing.T) {

	code := `
resource "aws_s3_bucket" "testA" {
  bucket = "com.test.testA"
}

resource "aws_s3_bucket_acl" "testA" {
  bucket = aws_s3_bucket.testA.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "testA" {
  bucket = aws_s3_bucket.testA.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "testB" {
  bucket = "com.test.testB"
}

resource "aws_s3_bucket_acl" "testB" {
  bucket = aws_s3_bucket.testB.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "testB" {
  bucket = aws_s3_bucket.testB.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

`

	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": code,
	})

	scanner := New()

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	for _, result := range results.GetFailed() {
		// public access block
		assert.NotEqual(t, "AVD-AWS-0094", result.Rule().AVDID)
	}

}

// PoC for replacing Go with Rego: AVD-AWS-0001
func Test_RegoRules(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_apigatewayv2_stage" "bad_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"
}
`,
		"/rules/test.rego": `# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0001
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: apigateway
#           provider: aws
package builtin.cloud.AWS0001

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
	stage := api.stages[_]
	isManaged(stage)
	stage.accesslogging.cloudwatchloggrouparn.value == ""
	res := result.new("Access logging is not configured.", stage.accesslogging.cloudwatchloggrouparn)
}

deny[res] {
	api := input.aws.apigateway.v2.apis[_]
	stage := api.stages[_]
	isManaged(stage)
	stage.accesslogging.cloudwatchloggrouparn.value == ""
	res := result.new("Access logging is not configured.", stage.accesslogging.cloudwatchloggrouparn)
}
`,
	})

	scanner := New(
		rego.WithPolicyFilesystem(fs),
		rego.WithPolicyDirs("rules"),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]

	assert.Equal(t, "AVD-AWS-0001", failure.Rule().AVDID)

	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     2,
			Content:    "resource \"aws_apigatewayv2_stage\" \"bad_example\" {",
			IsCause:    true,
			FirstCause: true,
			LastCause:  false,
			Annotation: "",
		},
		{
			Number:     3,
			Content:    "  api_id = aws_apigatewayv2_api.example.id",
			IsCause:    true,
			FirstCause: false,
			LastCause:  false,
			Annotation: "",
		},
		{
			Number:     4,
			Content:    "  name   = \"example-stage\"",
			IsCause:    true,
			FirstCause: false,
			LastCause:  false,
			Annotation: "",
		},
		{
			Number:     5,
			Content:    "}",
			IsCause:    true,
			FirstCause: false,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

func Test_OptionWithConfigsFileSystem(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": `
variable "bucket_name" {
  type = string
}
resource "aws_s3_bucket" "main" {
  bucket = var.bucket_name
}
`,
		"rules/bucket_name.rego": emptyBucketCheck,
	})

	configsFS := testutil.CreateFS(t, map[string]string{
		"main.tfvars": `
bucket_name = "test"
`,
	})

	scanner := New(
		rego.WithPolicyNamespaces("user"),
		rego.WithPolicyDirs("rules"),
		rego.WithPolicyFilesystem(fs),
		rego.WithEmbeddedLibraries(false),
		rego.WithEmbeddedPolicies(false),
		ScannerWithAllDirectories(true),
		ScannerWithTFVarsPaths("main.tfvars"),
		ScannerWithConfigsFileSystem(configsFS),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.Len(t, results.GetPassed(), 1)
}

func Test_OptionWithConfigsFileSystem_ConfigInCode(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": `
variable "bucket_name" {
  type = string
}
resource "aws_s3_bucket" "main" {
  bucket = var.bucket_name
}
`,
		"rules/bucket_name.rego": emptyBucketCheck,
		"main.tfvars": `
bucket_name = "test"
`,
	})

	scanner := New(
		rego.WithPolicyNamespaces("user"),
		rego.WithPolicyDirs("rules"),
		rego.WithPolicyFilesystem(fs),
		rego.WithEmbeddedLibraries(false),
		rego.WithEmbeddedPolicies(false),
		ScannerWithAllDirectories(true),
		ScannerWithTFVarsPaths("main.tfvars"),
		ScannerWithConfigsFileSystem(fs),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.Len(t, results.GetPassed(), 1)
}

func Test_DoNotScanNonRootModules(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"/code/app1/main.tf": `
module "s3" {
  source      = "./modules/s3"
  bucket_name = "test"
}
`,
		"/code/app1/modules/s3/main.tf": `
variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "main" {
  bucket = var.bucket_name
}
`,
		"/code/app1/app2/main.tf": `
module "s3" {
  source      = "../modules/s3"
  bucket_name = "test"
}

module "ec2" {
  source = "./modules/ec2"
}
`,
		"/code/app1/app2/modules/ec2/main.tf": `
variable "security_group_description" {
	type = string
}
resource "aws_security_group" "main" {
	description = var.security_group_description
}
`,
		"/rules/bucket_name.rego": emptyBucketCheck,
		"/rules/sec_group_description.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0002
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: ec2
#           provider: aws
package defsec.test.aws2
deny[res] {
  group := input.aws.ec2.securitygroups[_]
  group.description.value == ""
  res := result.new("The description of the security group must not be empty", group)
}
`,
	})

	scanner := New(
		rego.WithPolicyNamespaces("user"),
		rego.WithPolicyFilesystem(fs),
		rego.WithPolicyDirs("rules"),
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(false),
		ScannerWithAllDirectories(true),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	assert.Len(t, results.GetPassed(), 2)
	require.Len(t, results.GetFailed(), 1)
	assert.Equal(t, "AVD-AWS-0002", results.GetFailed()[0].Rule().AVDID)
}

func Test_RoleRefToOutput(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": `
module "this" {
  source = "./modules/iam"
}

resource "aws_iam_role_policy" "bad-policy" {
  name     = "bad-policy"
  role     = module.this.role_name
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}
		`,
		"code/modules/iam/main.tf": `
resource "aws_iam_role" "example" {
  name               = "example"
  assume_role_policy = jsonencode({})
}

output "role_name" {
  value = aws_iam_role.example.id
}
		`,
		"rules/test.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0001
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package defsec.test.aws1
deny[res] {
  policy := input.aws.iam.roles[_].policies[_]
  policy.name.value == "bad-policy"
  res := result.new("Deny!", policy)
}
`,
	})

	scanner := New(
		rego.WithPolicyDirs("rules"),
		rego.WithPolicyFilesystem(fs),
		rego.WithEmbeddedLibraries(false),
		rego.WithEmbeddedPolicies(false),
		ScannerWithAllDirectories(true),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_RegoRefToAwsProviderAttributes(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"code/providers.tf": `
provider "aws" {
  region  = "us-east-2"
  default_tags {
    tags = {
      Environment = "Local"
      Name        = "LocalStack"
    }
  }
}
`,
		"rules/region.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0001
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: meta
#           provider: aws
package defsec.test.aws1
deny[res] {
  region := input.aws.meta.tfproviders[_].region
  region.value != "us-east-1"
  res := result.new("Only the 'us-east-1' region is allowed!", region)
}
`,
		"rules/tags.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0002
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: meta
#           provider: aws
package defsec.test.aws2
deny[res] {
  provider := input.aws.meta.tfproviders[_]
  tags = provider.defaulttags.tags.value
  not tags.Environment
  res := result.new("provider should have the following default tags: 'Environment'", tags)
}`,
	})

	scanner := New(
		rego.WithPolicyDirs("rules"),
		rego.WithPolicyFilesystem(fs),
		rego.WithEmbeddedLibraries(false),
		rego.WithEmbeddedPolicies(false),
		ScannerWithAllDirectories(true),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results, 2)

	require.Len(t, results.GetFailed(), 1)
	assert.Equal(t, "AVD-AWS-0001", results.GetFailed()[0].Rule().AVDID)

	require.Len(t, results.GetPassed(), 1)
	assert.Equal(t, "AVD-AWS-0002", results.GetPassed()[0].Rule().AVDID)
}

func TestScanModuleWithCount(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": `
module "this" {
  count = 0
  source = "./modules/s3"
}`,
		"code/modules/s3/main.tf": `
module "this" {
  source = "./modules/logging"
}
resource "aws_s3_bucket" "this" {
  bucket = "test"
}`,
		"code/modules/s3/modules/logging/main.tf": `
resource "aws_s3_bucket" "this" {
  bucket = "test1"
}`,
		"code/example/main.tf": `
module "this" {
  source = "../modules/s3"
}`,
		"rules/region.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0001
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package user.test.aws1
deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "test"
  res := result.new("bucket with test name is not allowed!", bucket)
}
`,
	})

	scanner := New(
		rego.WithPolicyDirs("rules"),
		rego.WithPolicyFilesystem(fs),
		rego.WithPolicyNamespaces("user"),
		rego.WithEmbeddedLibraries(false),
		rego.WithEmbeddedPolicies(false),
		rego.WithRegoErrorLimits(0),
		ScannerWithAllDirectories(true),
	)

	results, err := scanner.ScanFS(t.Context(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results, 1)

	failed := results.GetFailed()

	assert.Len(t, failed, 1)

	occurrences := failed[0].Occurrences()
	assert.Equal(t, "code/example/main.tf", occurrences[0].Filename)
}

func TestSkipDir(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"deployments/main.tf": `
module "use_bad_configuration" {
  source = "../modules"
}

module "use_bad_configuration_2" {
  source = "../modules/modules2"
}
`,
		"modules/misconfig.tf": `
resource "aws_s3_bucket" "test" {}
`,
		"modules/modules2/misconfig.tf": `
resource "aws_s3_bucket" "test" {}
`,
	})

	t.Run("use skip-dir option", func(t *testing.T) {
		scanner := New(
			ScannerWithSkipDirs([]string{"**/modules/**"}),
			ScannerWithAllDirectories(true),
			rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
			rego.WithPolicyNamespaces("user"),
		)

		results, err := scanner.ScanFS(t.Context(), fsys, "deployments")
		require.NoError(t, err)

		assert.Empty(t, results)
	})

	t.Run("use skip-files option", func(t *testing.T) {
		scanner := New(
			ScannerWithSkipFiles([]string{"**/modules/**/*.tf"}),
			ScannerWithAllDirectories(true),
			rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
			rego.WithPolicyNamespaces("user"),
		)

		results, err := scanner.ScanFS(t.Context(), fsys, "deployments")
		require.NoError(t, err)

		assert.Empty(t, results)
	})

	t.Run("non existing value for skip-files option", func(t *testing.T) {
		scanner := New(
			ScannerWithSkipFiles([]string{"foo/bar*.tf"}),
			ScannerWithAllDirectories(true),
			rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
			rego.WithPolicyNamespaces("user"),
		)

		results, err := scanner.ScanFS(t.Context(), fsys, "deployments")
		require.NoError(t, err)

		assert.Len(t, results, 2)
	})

	t.Run("empty skip-files option", func(t *testing.T) {
		scanner := New(
			ScannerWithAllDirectories(true),
			rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
			rego.WithPolicyNamespaces("user"),
		)

		results, err := scanner.ScanFS(t.Context(), fsys, "deployments")
		require.NoError(t, err)

		assert.Len(t, results, 2)
	})
}

func TestUseRandomProvider(t *testing.T) {
	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(`resource "random_id" "suffix" {}

locals {
  bucket = "test-${random_id.suffix.hex}"
}

resource "aws_s3_bucket" "test" {
  bucket = local.bucket
}

resource "aws_s3_bucket_versioning" "test" {
  bucket = local.bucket
  versioning_configuration {
    status = "Enabled"
  }
}
`)},
	}

	check := `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package test
import rego.v1

deny contains res if {
  some bucket in input.aws.s3.buckets
  bucket.versioning.enabled.value
  res := result.new("Bucket versioning is enabled", bucket)
}
`

	scanner := New(
		ScannerWithAllDirectories(true),
		rego.WithPolicyReader(strings.NewReader(check)),
		rego.WithPolicyNamespaces("test"),
	)

	results, err := scanner.ScanFS(t.Context(), fsys, ".")
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
}

func TestRenderedCause(t *testing.T) {

	s3check := `# METADATA
# title: S3 Data should be versioned
# custom:
#   id: AVD-AWS-0090
#   avd_id: AVD-AWS-0090
package user.aws.s3.aws0090

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.versioning.enabled.value
	res := result.new(
		"Bucket does not have versioning enabled",
		bucket.versioning.enabled
	)
}
`
	iamcheck := `# METADATA
# title: Service accounts should not have roles assigned with excessive privileges
# custom:
#   id: AVD-GCP-0007
#   avd_id: AVD-GCP-0007
package user.google.iam.google0007

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.all_members
	print(member)
	iam.is_service_account(member.member.value)
	iam.is_role_privileged(member.role.value)
	res := result.new("Service account is granted a privileged role.", member.role)
}

deny contains res if {
	some binding in iam.all_bindings
	iam.is_role_privileged(binding.role.value)
	some member in binding.members
	iam.is_service_account(member.value)
	res := result.new("Service account is granted a privileged role.", member)
}
`

	tests := []struct {
		name              string
		inputCheck        string
		fsys              fstest.MapFS
		expected          string
		expectedStartLine int
		expectedEndLine   int
	}{
		{
			name:       "just misconfigured resource",
			inputCheck: s3check,
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`
locals {
	versioning = false
}

resource "aws_s3_bucket" "test" {
	bucket = "test"

	versioning {
		enabled = local.versioning
	}
}
`)},
			},
			expected: `resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}`,
		},
		{
			name:       "misconfigured resource instance",
			inputCheck: s3check,
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`
locals {
	versioning = false
}

resource "aws_s3_bucket" "test" {
	count = 1
	bucket = "test"

	versioning {
		enabled = local.versioning
	}
}
`)},
			},
			expected: `resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}`,
		},
		{
			name:       "misconfigured resource instance in the module",
			inputCheck: s3check,
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`
module "bucket" {
	source = "../modules/bucket"
}
`),
				},
				"modules/bucket/main.tf": &fstest.MapFile{Data: []byte(`
locals {
  versioning = false
}

resource "aws_s3_bucket" "test" {
  count = 1
  bucket = "test"

  versioning {
    enabled = local.versioning
  }
}`)},
			},
			expected: `resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}`,
		},
		{
			name:       "misconfigured resource",
			inputCheck: iamcheck,
			fsys: fstest.MapFS{`main.tf`: &fstest.MapFile{Data: []byte(`
resource "google_storage_bucket_iam_binding" "service-a" {
  bucket = google_storage_bucket.service-a.name
  role   = "roles/storage.objectAdmin"

  members = [
    "serviceAccount:service-a@example-project.iam.gserviceaccount.com"
  ]
}`),
			}},
			expectedStartLine: 6,
			expectedEndLine:   8,
		},
		{
			name:       "dont panic on unknown value",
			inputCheck: iamcheck,
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`
resource "google_storage_bucket_iam_binding" "service-a" {
  bucket = google_storage_bucket.service-a.name
  role   = "roles/storage.objectAdmin"

  members = [
    "serviceAccount:service-a@example-project.iam.gserviceaccount.com",
    data.google_storage_transfer_project_service_account.production.member,
  ]
}

data "google_storage_transfer_project_service_account" "production" {
  project = local.project_id
}
`)},
			},
			expectedStartLine: 6,
			expectedEndLine:   9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := New(
				ScannerWithAllDirectories(true),
				rego.WithEmbeddedLibraries(true),
				rego.WithPolicyReader(strings.NewReader(tt.inputCheck)),
				rego.WithPolicyNamespaces("user"),
			)

			results, err := scanner.ScanFS(t.Context(), tt.fsys, ".")
			require.NoError(t, err)

			failed := results.GetFailed()

			assert.Len(t, failed, 1)

			if tt.expected != "" {
				assert.Equal(t, tt.expected, failed[0].Flatten().RenderedCause.Raw)
			} else {
				assert.Equal(t, tt.expectedStartLine, failed[0].Flatten().Location.StartLine)
				assert.Equal(t, tt.expectedEndLine, failed[0].Flatten().Location.EndLine)
			}
		})
	}
}

func TestScanRawTerraform(t *testing.T) {
	check := `# METADATA
# title: Buckets should not be evil
# schemas:
# - input: schema["terraform-raw"]
# custom:
#   id: USER0001
#   short_code: evil-bucket
#   severity: HIGH
#   input:
#     selector:
#     - type: terraform-raw
package user.bucket001

import rego.v1

deny contains res if {
	some block in input.modules[_].blocks
	block.kind == "resource"
	block.type == "aws_s3_bucket"
	name := block.attributes["bucket"]
	name.value == "evil"
	res := result.new("Buckets should not be evil", name)
}`

	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(`resource "aws_s3_bucket" "test" {
  bucket = "evil"		
}`)},
	}

	scanner := New(
		ScannerWithAllDirectories(true),
		options.WithScanRawConfig(true),
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyReader(strings.NewReader(check)),
		rego.WithPolicyNamespaces("user"),
	)

	results, err := scanner.ScanFS(t.Context(), fsys, ".")
	require.NoError(t, err)

	failed := results.GetFailed()

	assert.Len(t, failed, 1)
}
