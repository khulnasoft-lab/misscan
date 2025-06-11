package codebuild

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	Metadata                  misscanTypes.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	Metadata          misscanTypes.Metadata
	EncryptionEnabled misscanTypes.BoolValue
}
