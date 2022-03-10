// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_model

// ---------------------------------------------------
// 					Event Json
// ---------------------------------------------------

type EventJson struct {
	GroupName              string      `json:"groupName"`
	NodeID                 string      `json:"nodeId"`
	CustomerID             int         `json:"customerId"`
	EmailID                string      `json:"emailId"`
	CollectorVersion       string      `json:"collectorVersion"`
	JSONName               string      `json:"jsonName"`
	JSONVersion            string      `json:"jsonVersion"`
	BuildNumber            string      `json:"buildNumber"`
	PolicyVersion          string      `json:"policyVersion"`
	Language               string      `json:"language"`
	Framework              string      `json:"framework"`
	CollectorType          string      `json:"collectorType"`
	Pid                    string      `json:"pid"`
	ApplicationUUID        string      `json:"applicationUUID"`
	StartTime              string      `json:"startTime"`
	SourceMethod           string      `json:"sourceMethod"`
	UserFileName           string      `json:"userFileName"`
	UserMethodName         string      `json:"userMethodName"`
	LineNumber             string      `json:"lineNumber"`
	Parameters             interface{} `json:"parameters"`
	EventGenerationTime    string      `json:"eventGenerationTime"`
	HTTPRequest            RequestInfo `json:"httpRequest"`
	ID                     string      `json:"id"`
	Stacktrace             interface{} `json:"stacktrace"`
	CompleteStacktrace     interface{} `json:"completeStacktrace"`
	CaseType               string      `json:"caseType"`
	EventCategory          string      `json:"eventCategory"`
	MetaData               MetaData    `json:"metaData"`
	BlockingProcessingTime string      `json:"blockingProcessingTime"`
	IsAPIBlocked           bool        `json:"isAPIBlocked"`
	APIID                  string      `json:"apiId"`
	IsIASTEnable           bool        `json:"isIASTEnable"`
}

type MetaData struct {
	TriggerViaRCI             bool `json:"triggerViaRCI"`
	TriggerViaDeserialisation bool `json:"triggerViaDeserialisation"`
	TriggerViaXXE             bool `json:"triggerViaXXE"`
	IsClientDetectedFromXFF   bool `json:"isClientDetectedFromXFF"`
	//RciMethodsCalls           []interface{} `json:"rciMethodsCalls"`
	APIBlocked bool `json:"apiBlocked"`
	//Ips                       []string      `json:"ips"`
}

type RequestInfo struct {
	Body         string            `json:"body"`
	Headers      map[string]string `json:"headers"`
	URL          string            `json:"url"`
	RawRequest   string            `json:"rawRequest"`
	Method       string            `json:"method"`
	ContentType  string            `json:"contentType"`
	ContextPath  string            `json:"contextPath"`
	ClientIP     string            `json:"clientIP"`
	ClientPort   string            `json:"clientPort"`
	ServerPort   string            `json:"serverPort"`
	Protocol     string            `json:"protocol"`
	ParameterMap interface{}       `json:"parameterMap"`
	IsGRPC       bool              `json:"isGrpc"`
	ServerName   string            `json:"serverName"`
}

// ---------------------------------------------------
// 					Appliation info
// ---------------------------------------------------

type ApplicationInfo struct {
	CollectorVersion            string                      `json:"collectorVersion"`
	JSONName                    string                      `json:"jsonName"`
	JSONVersion                 string                      `json:"jsonVersion"`
	PolicyVersion               string                      `json:"policyVersion"`
	CollectorType               string                      `json:"collectorType"`
	BuildNumber                 string                      `json:"buildNumber"`
	GroupName                   string                      `json:"groupName"`
	NodeID                      string                      `json:"nodeId"`
	CustomerID                  int                         `json:"customerId"`
	EmailID                     string                      `json:"emailId"`
	Language                    string                      `json:"language"`
	Framework                   string                      `json:"framework"`
	Sha256                      string                      `json:"sha256"`
	Pid                         string                      `json:"pid"`
	ApplicationUUID             string                      `json:"applicationUUID"`
	Cmdline                     []string                    `json:"cmdline"`
	StartTime                   string                      `json:"startTime"`
	RunCommand                  string                      `json:"runCommand"`
	UserDir                     string                      `json:"userDir"`
	ServerInfo                  map[string]interface{}      `json:"serverInfo"`
	BootLibraryPath             string                      `json:"bootLibraryPath"`
	BinaryName                  string                      `json:"binaryName"`
	BinaryVersion               string                      `json:"binaryVersion"`
	OsArch                      string                      `json:"osArch"`
	OsName                      string                      `json:"osName"`
	OsVersion                   string                      `json:"osVersion"`
	BinaryPath                  string                      `json:"binaryPath"`
	AgentAttachmentType         string                      `json:"agentAttachmentType"`
	Identifier                  map[string]interface{}      `json:"identifier"`
	UserProvidedApplicationInfo UserProvidedApplicationInfo `json:"userProvidedApplicationInfo"`
}

type UserProvidedApplicationInfo struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Tags    []string `json:"tags"`
}

// ---------------------------------------------------
// 					LAhealthcheck
// ---------------------------------------------------

type LAhealthcheck struct {
	CollectorVersion        string   `json:"collectorVersion"`
	JSONName                string   `json:"jsonName"`
	JSONVersion             string   `json:"jsonVersion"`
	PolicyVersion           string   `json:"policyVersion"`
	CollectorType           string   `json:"collectorType"`
	GroupName               string   `json:"groupName"`
	BuildNumber             string   `json:"buildNumber"`
	NodeID                  string   `json:"nodeId"`
	CustomerID              int      `json:"customerId"`
	EmailID                 string   `json:"emailId"`
	Language                string   `json:"language"`
	Framework               string   `json:"framework"`
	ApplicationUUID         string   `json:"applicationUUID"`
	ProtectedServer         string   `json:"protectedServer"`
	ProtectedDB             []string `json:"protectedDB"`
	EventDropCount          uint64   `json:"eventDropCount"`
	IsHost                  bool     `json:"isHost"`
	EventProcessed          uint64   `json:"eventProcessed"`
	EventSentCount          uint64   `json:"eventSentCount"`
	HTTPRequestCount        uint64   `json:"httpRequestCount"`
	ProtectedVulnerabilties []string `json:"protectedVulnerabilties"`
}

// ---------------------------------------------------
// 					HttpConnectionStat
// ---------------------------------------------------

type HttpConnectionStat struct {
	CollectorVersion string            `json:"collectorVersion"`
	JSONName         string            `json:"jsonName"`
	JSONVersion      string            `json:"jsonVersion"`
	PolicyVersion    string            `json:"policyVersion"`
	GroupName        string            `json:"groupName"`
	BuildNumber      string            `json:"buildNumber"`
	NodeID           string            `json:"nodeId"`
	CustomerID       int               `json:"customerId"`
	EmailID          string            `json:"emailId"`
	CollectorType    string            `json:"collectorType"`
	Language         string            `json:"language"`
	Framework        string            `json:"framework"`
	HTTPConnections  []HTTPConnections `json:"httpConnections"`
	ApplicationUUID  string            `json:"applicationUUID"`
	IsCached         bool              `json:"isCached"`
}

type HTTPConnections struct {
	URL             string    `json:"url"`
	SourceIP        string    `json:"sourceIp"`
	DestinationIP   string    `json:"destinationIp"`
	DestinationPort uint64    `json:"destinationPort"`
	Direction       string    `json:"direction"`
	Count           uint64    `json:"count"`
	SourceID        *SourceID `json:"sourceId,omitempty"`
}

type SourceID struct {
	ApplicationUUID string `json:"applicationUUID"`
	ContextPath     string `json:"contextPath"`
	ServerPort      string `json:"serverPort"`
	Target          string `json:"target"`
}

// ---------------------------------------------------
// 					GRPC BODY
// ---------------------------------------------------
type Grpcbody struct {
	K2Body []interface{} `json:"k2body"`
}

// ---------------------------------------------------
// 					GRPC BODY Fuzz
// ---------------------------------------------------
type GrpcbodyFuzz struct {
	K2Body []interface{} `json:"k2body"`
}

type Exitevent struct {
	GroupName           string `json:"groupName"`
	BuildNumber         string `json:"buildNumber"`
	NodeID              string `json:"nodeId"`
	CustomerID          int    `json:"customerId"`
	EmailID             string `json:"emailId"`
	JSONName            string `json:"jsonName"`
	JSONVersion         string `json:"jsonVersion"`
	PolicyVersion       string `json:"policyVersion"`
	ExecutionId         string `json:"executionId"`
	CaseType            string `json:"caseType"`
	ApplicationUUID     string `json:"applicationUUID"`
	K2RequestIdentifier string `json:"k2RequestIdentifier"`
}
