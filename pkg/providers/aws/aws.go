package aws

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/accessanalyzer"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/apigateway"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/athena"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudfront"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudwatch"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/codebuild"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/config"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/dynamodb"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecr"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ecs"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/efs"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/eks"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elasticache"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elasticsearch"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elb"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/emr"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kinesis"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/kms"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/lambda"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/mq"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/msk"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/neptune"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/redshift"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sns"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sqs"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ssm"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/workspaces"
)

type AWS struct {
	Meta           Meta
	AccessAnalyzer accessanalyzer.AccessAnalyzer
	APIGateway     apigateway.APIGateway
	Athena         athena.Athena
	Cloudfront     cloudfront.Cloudfront
	CloudTrail     cloudtrail.CloudTrail
	CloudWatch     cloudwatch.CloudWatch
	CodeBuild      codebuild.CodeBuild
	Config         config.Config
	DocumentDB     documentdb.DocumentDB
	DynamoDB       dynamodb.DynamoDB
	EC2            ec2.EC2
	ECR            ecr.ECR
	ECS            ecs.ECS
	EFS            efs.EFS
	EKS            eks.EKS
	ElastiCache    elasticache.ElastiCache
	Elasticsearch  elasticsearch.Elasticsearch
	ELB            elb.ELB
	EMR            emr.EMR
	IAM            iam.IAM
	Kinesis        kinesis.Kinesis
	KMS            kms.KMS
	Lambda         lambda.Lambda
	MQ             mq.MQ
	MSK            msk.MSK
	Neptune        neptune.Neptune
	RDS            rds.RDS
	Redshift       redshift.Redshift
	SAM            sam.SAM
	S3             s3.S3
	SNS            sns.SNS
	SQS            sqs.SQS
	SSM            ssm.SSM
	WorkSpaces     workspaces.WorkSpaces
}

type Meta struct {
	TFProviders []TerraformProvider
}
