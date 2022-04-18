// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_model

// ---- GlobalData struct used to store all data related to Agent Policy ------
type GlobalData struct {
	PartialStacktrace  bool `default:"false"`
	DynamicScanning    bool `default:"false"`
	ProtectionMode     bool `default:"false"`
	IpBlocking         bool `default:"false"`
	ApiBlocking        bool `default:"false"`
	PolicyParameters   PolicyParameters
	ProtectAllApis     bool   `default:"false"`
	ProtectAttackApis  bool   `default:"false"`
	IpDetectViaXFF     bool   `default:"false"`
	PolicyPull         bool   `default:"true"`
	PolicyPullInterval int    `default:"60"`
	PolicyVersion      string `default:"DEFAULT"`
}

//version testing
// ---- AgentPolicy struct used handle CC 100 ------
type AgentPolicy struct {
	IastMode struct {
		Enabled        bool `json:"enabled"`
		StaticScanning struct {
			Enabled                     bool `json:"enabled"`
			CveDefinitionUpdateInterval int  `json:"cveDefinitionUpdateInterval"`
			ContainerScan               struct {
				Enabled         bool `json:"enabled"`
				UpdateInterval  int  `json:"updateInterval"`
				NumberOfRetries int  `json:"numberOfRetries"`
			} `json:"containerScan"`
		} `json:"staticScanning"`
		DynamicScanning struct {
			Enabled                  bool `json:"enabled"`
			ReportGenerationInterval int  `json:"reportGenerationInterval"`
			Probing                  struct {
				Interval  int `json:"interval"`
				BatchSize int `json:"batchSize"`
			} `json:"probing"`
			ReportServerPort   int  `json:"reportServerPort"`
			ReportServerEnable bool `json:"reportServerEnable"`
		} `json:"dynamicScanning"`
		EnableSaveScanResultsLocally bool `json:"enableSaveScanResultsLocally"`
		EnableHooks                  bool `json:"enableHooks"`
	} `json:"iastMode"`
	ProtectionMode struct {
		Enabled    bool `json:"enabled"`
		IPBlocking struct {
			Enabled            bool   `json:"enabled"`
			AttackerIPBlocking bool   `json:"attackerIpBlocking"`
			IPDetectViaXFF     bool   `json:"ipDetectViaXFF"`
			Timeout            int    `json:"timeout"`
			ParameterFilePath  string `json:"parameterFilePath"`
		} `json:"ipBlocking"`
		APIBlocking struct {
			Enabled                    bool `json:"enabled"`
			ProtectAllApis             bool `json:"protectAllApis"`
			ProtectKnownVulnerableApis bool `json:"protectKnownVulnerableApis"`
			ProtectAttackedApis        bool `json:"protectAttackedApis"`
		} `json:"apiBlocking"`
	} `json:"protectionMode"`
	SendCompleteStackTrace bool `json:"sendCompleteStackTrace"`
}

// ---- AgentInfo struct used handle CC 10 ------
type AgentInfo struct {
	Timestamp int64 `json:"timestamp"`
	AgentInfo struct {
		K2Version   string `json:"k2Version"`
		K2ICToolID  string `json:"k2ICToolId"`
		JSONVersion string `json:"jsonVersion"`
		CustomerID  int    `json:"customerId"`
		NodeIP      string `json:"nodeIp"`
		NodeID      string `json:"nodeId"`
		NodeName    string `json:"nodeName"`
	} `json:"agentInfo"`
	StartupProperties struct {
		LogLevel      string `json:"logLevel"`
		DeploymentEnv string `json:"deploymentEnv"`
		FtpProperties struct {
			EnableFtp bool   `json:"enableFtp"`
			Port      int    `json:"port"`
			Username  string `json:"username"`
			Password  string `json:"password"`
		} `json:"ftpProperties"`
		PrintHTTPRequest bool `json:"printHttpRequest"`
	} `json:"startupProperties"`
}

// ---- K2ControlCode101_struct struct used handle CC 101 ------
type K2ControlCode101_struct struct {
	ControlCommand int        `json:"controlCommand"`
	Arguments      []string   `json:"arguments"`
	Data           K2Blocking `json:"data"`
}

// ---- control-code 11 - Fuzz -----
type Fuzz_struct struct {
	QueryString      string                 `"json:queryString"`
	ClientIP         string                 `"json:clientIP"`
	ClientPort       string                 `"json:clientPort"`
	DataTruncated    bool                   `"json:dataTruncated"`
	ContentType      string                 `"json:contentType"`
	RequestURI       string                 `"json:requestURI"`
	GenerationTime   int64                  `"json:generationTime"`
	Body             string                 `"json:body"`
	Method           string                 `"json:method"`
	Url              string                 `"json:url"`
	Headers          map[string]interface{} `"json:headers"`
	WhitelistedIPs   []string               `json:"whitelistedIPs"`
	ContextPath      string                 `json:"contextPath"`
	PathParams       string                 `json:"pathParams"`
	Protocol         string                 `json:"protocol"`
	Parts            string                 `json:"parts"`
	ServerPort       int                    `json:"serverPort"`
	PathParameterMap map[string]interface{} `"json:pathParameterMap"`
	ParameterMap     map[string]interface{} `"json:parameterMap"`
	IsGRPC           bool                   `json:"isGrpc"`
	ServerName       string                 `json:"serverName"`
}

// ---- control-code -----
type K2ControlComand struct {
	ControlCommand int         `json:"controlCommand"`
	Arguments      []string    `json:"arguments"`
	Data           interface{} `json:"data"`
}

// Blocking
type K2Blocking struct {
	Version              string        `json:"version"`
	Timestamp            int64         `json:"timestamp"`
	LastUpdateTimestamp  int64         `json:"lastUpdateTimestamp"`
	LastFetchTime        int           `json:"lastFetchTime"`
	AttackerIPTimeout    int           `json:"attackerIpTimeout"`
	PolicyPullInterval   int           `json:"policyPullInterval"`
	AllowedIps           []interface{} `json:"allowedIps"`
	BlockedIps           []string      `json:"blockedIps"`
	AllowedApis          []interface{} `json:"allowedApis"`
	BlockedApis          []interface{} `json:"blockedApis"`
	AllowedRequests      []interface{} `json:"allowedRequests"`
	AdditionalProperties interface{}   `json:"additionalProperties"`
}

// ---- fuzz fail event -----

type FuzzFailBean struct {
	CollectorVersion string `json:"collectorVersion"`
	JSONName         string `json:"jsonName"`
	JSONVersion      string `json:"jsonVersion"`
	Language         string `json:"language"`
	Framework        string `json:"framework"`
	CollectorType    string `json:"collectorType"`
	FuzzHeader       string `json:"fuzzHeader"`
	ApplicationUUID  string `json:"applicationUUID"`
	BuildNumber      string `json:"buildNumber"`
	PolicyVersion    string `json:"policyVersion"`
	GroupName        string `json:"groupName"`
	NodeID           string `json:"nodeId"`
	CustomerID       int    `json:"customerId"`
	EmailID          string `json:"emailId"`
}

// ---------------------------------------------------
// struct: Info_struct - our state
// ---------------------------------------------------
type Info_req struct {
	//---- incoming request fields ---- move to thread-specific when MT -- TODO
	Body                string
	HeaderMap           map[string]string
	Url                 string //for grpc ServiceName/MethodName
	Queryparam          map[string][]string
	RawRequest          string
	Method              string //GET POST GRPC
	ContentType         string
	ResponseBody        string // for grpc responseString
	Protocol            string
	ClientIp            string
	ClientPort          string
	ServerPort          string
	GrpcByte            [][]byte
	IsGrpc              bool
	GrpcBody            []interface{}
	ApiId               string
	Stacktrace          []string
	K2TraceData         string
	K2RequestIdentifier string
	ServerName          string
	//------------------------------------------------------------------------
}

type Info_grpc struct {
	ClientIp   string
	ClientPort string
}
