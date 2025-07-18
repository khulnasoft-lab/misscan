package ssm

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ssm"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

func getSecrets(ctx parser.FileContext) (secrets []ssm.Secret) {
	for _, r := range ctx.GetResourcesByType("AWS::SecretsManager::Secret") {
		secret := ssm.Secret{
			Metadata: r.Metadata(),
			KMSKeyID: r.GetStringProperty("KmsKeyId"),
		}

		secrets = append(secrets, secret)
	}
	return secrets
}
