// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_model

import "time"

type EventData struct {
	EventCount        uint64
	DropEventCount    uint64
	RequestCount      uint64
	EventProcessCount uint64
}

type GoAgentInfo struct {
	K2validator   string
	K2resource    string
	SecureWSready bool
	Hooked        bool
	GlobalData    GlobalData
}

type EnvironmentInfo struct {
	ID                string
	NodeId            string
	NodeIp            string
	NodeName          string
	CollectorIp       string
	GroupName         string
	NodeGroupTags     []string
	RunningEnv        string
	Namespaces        string
	ContainerId       string
	PodId             string
	Wd                string
	Gopath            string
	Goarch            string
	Goos              string
	Goroot            string
	NlcPath           string
	AlcPath           string
	UserAppName       string
	UserAppVersion    string
	UserAppTags       string
	EcsTaskId         string
	ImageId           string
	Image             string
	ContainerName     string
	EcsTaskDefinition string
}

type RunningApplicationInfo struct {
	AppName         string
	ProtectedServer string
	AppUUID         string
	Sha256          string
	Size            string
	ContextPath     string
	Pid             string
	Cmd             string
	Cmdline         []string
	Ports           []int
	ServerIp        string
	Starttimestr    string
	BinaryPath      string
	ServerName      []string
}

type EcsData struct {
	DockerID   string `json:"DockerId"`
	Name       string `json:"Name"`
	DockerName string `json:"DockerName"`
	Image      string `json:"Image"`
	ImageID    string `json:"ImageID"`
	Labels     struct {
		ComAmazonawsEcsCluster               string `json:"com.amazonaws.ecs.cluster"`
		ComAmazonawsEcsContainerName         string `json:"com.amazonaws.ecs.container-name"`
		ComAmazonawsEcsTaskArn               string `json:"com.amazonaws.ecs.task-arn"`
		ComAmazonawsEcsTaskDefinitionFamily  string `json:"com.amazonaws.ecs.task-definition-family"`
		ComAmazonawsEcsTaskDefinitionVersion string `json:"com.amazonaws.ecs.task-definition-version"`
	} `json:"Labels"`
	DesiredStatus string `json:"DesiredStatus"`
	KnownStatus   string `json:"KnownStatus"`
	Limits        struct {
		CPU int `json:"CPU"`
	} `json:"Limits"`
	CreatedAt time.Time `json:"CreatedAt"`
	StartedAt time.Time `json:"StartedAt"`
	Type      string    `json:"Type"`
	Networks  []struct {
		NetworkMode   string   `json:"NetworkMode"`
		IPv4Addresses []string `json:"IPv4Addresses"`
	} `json:"Networks"`
}
