// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_model

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
	ID             string
	NodeId         string
	NodeIp         string
	NodeName       string
	CollectorIp    string
	GroupName      string
	NodeGroupTags  []string
	RunningEnv     string
	Namespaces     string
	ContainerId    string
	PodId          string
	Wd             string
	Gopath         string
	Goarch         string
	Goos           string
	Goroot         string
	NlcPath        string
	AlcPath        string
	UserAppName    string
	UserAppVersion string
	UserAppTags    string
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
