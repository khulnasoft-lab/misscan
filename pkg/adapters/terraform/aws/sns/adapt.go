package sns

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sns"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) sns.SNS {
	return sns.SNS{
		Topics: adaptTopics(modules),
	}
}

func adaptTopics(modules terraform.Modules) []sns.Topic {
	var topics []sns.Topic
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sns_topic") {
			topics = append(topics, adaptTopic(resource))
		}
	}
	return topics
}

func adaptTopic(resourceBlock *terraform.Block) sns.Topic {
	return sns.Topic{
		Metadata:   resourceBlock.GetMetadata(),
		ARN:        types.StringDefault("", resourceBlock.GetMetadata()),
		Encryption: adaptEncryption(resourceBlock),
	}
}

func adaptEncryption(resourceBlock *terraform.Block) sns.Encryption {
	return sns.Encryption{
		Metadata: resourceBlock.GetMetadata(),
		KMSKeyID: resourceBlock.GetAttribute("kms_master_key_id").AsStringValueOrDefault("", resourceBlock),
	}
}
