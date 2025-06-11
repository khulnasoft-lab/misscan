package ecs

import (
	"encoding/json"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ECS struct {
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	Metadata misscanTypes.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	Metadata                 misscanTypes.Metadata
	ContainerInsightsEnabled misscanTypes.BoolValue
}

type TaskDefinition struct {
	Metadata             misscanTypes.Metadata
	Volumes              []Volume
	ContainerDefinitions []ContainerDefinition
}

func CreateDefinitionsFromString(metadata misscanTypes.Metadata, str string) ([]ContainerDefinition, error) {
	var containerDefinitionsJSON []containerDefinitionJSON
	if err := json.Unmarshal([]byte(str), &containerDefinitionsJSON); err != nil {
		return nil, err
	}
	var definitions []ContainerDefinition
	for _, j := range containerDefinitionsJSON {
		definitions = append(definitions, j.convert(metadata))
	}
	return definitions, nil
}

// see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html
type containerDefinitionJSON struct {
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	CPU          string            `json:"cpu"`
	Memory       string            `json:"memory"`
	Essential    bool              `json:"essential"`
	PortMappings []portMappingJSON `json:"portMappings"`
	EnvVars      []envVarJSON      `json:"environment"`
	Privileged   bool              `json:"privileged"`
}

type envVarJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type portMappingJSON struct {
	ContainerPort int `json:"containerPort"`
	HostPort      int `json:"hostPort"`
}

func (j containerDefinitionJSON) convert(metadata misscanTypes.Metadata) ContainerDefinition {
	var mappings []PortMapping
	for _, jMapping := range j.PortMappings {
		mappings = append(mappings, PortMapping{
			ContainerPort: misscanTypes.Int(jMapping.ContainerPort, metadata),
			HostPort:      misscanTypes.Int(jMapping.HostPort, metadata),
		})
	}

	var envVars []EnvVar
	for _, env := range j.EnvVars {
		envVars = append(envVars, EnvVar{
			Name:  misscanTypes.String(env.Name, metadata),
			Value: misscanTypes.String(env.Value, metadata),
		})
	}

	return ContainerDefinition{
		Metadata:     metadata,
		Name:         misscanTypes.String(j.Name, metadata),
		Image:        misscanTypes.String(j.Image, metadata),
		CPU:          misscanTypes.String(j.CPU, metadata),
		Memory:       misscanTypes.String(j.Memory, metadata),
		Essential:    misscanTypes.Bool(j.Essential, metadata),
		PortMappings: mappings,
		Environment:  envVars,
		Privileged:   misscanTypes.Bool(j.Privileged, metadata),
	}
}

type ContainerDefinition struct {
	Metadata     misscanTypes.Metadata
	Name         misscanTypes.StringValue
	Image        misscanTypes.StringValue
	CPU          misscanTypes.StringValue
	Memory       misscanTypes.StringValue
	Essential    misscanTypes.BoolValue
	PortMappings []PortMapping
	Environment  []EnvVar
	Privileged   misscanTypes.BoolValue
}

type EnvVar struct {
	Name  misscanTypes.StringValue
	Value misscanTypes.StringValue
}

type PortMapping struct {
	ContainerPort misscanTypes.IntValue
	HostPort      misscanTypes.IntValue
}

type Volume struct {
	Metadata               misscanTypes.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	Metadata                 misscanTypes.Metadata
	TransitEncryptionEnabled misscanTypes.BoolValue
}
