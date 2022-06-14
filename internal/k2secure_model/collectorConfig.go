// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_model

type RuntimeEnvironment string

const (
	KUBERNETES RuntimeEnvironment = "KUBERNETES"
	HOST       RuntimeEnvironment = "HOST"
	CONTAINER  RuntimeEnvironment = "CONTAINER"
)

type NodeLevelConfig struct {
	NodeId        string             `yaml:"nodeId"`
	NodeIp        string             `yaml:"nodeIp"`
	NodeName      string             `yaml:"nodeName"`
	NodeGroupTags []string           `yaml:"nodeGroupTags"`
	Runtime       RuntimeEnvironment `yaml:"runtime"`
	K2ServiceInfo K2ServiceInfo      `yaml:"k2ServiceInfo"`
	CustomerInfo  CustomerInfo       `yaml:"customerInfo"`
}

type K2ServiceInfo struct {
	ValidatorServiceEndpointURL string `yaml:"validatorServiceEndpointURL"`
	ResourceServiceEndpointURL  string `yaml:"resourceServiceEndpointURL"`
}

type CustomerInfo struct {
	CustomerId       int    `yaml:"customerId"`
	ApiAccessorToken string `yaml:"apiAccessorToken"`
	EmailId          string `yaml:"emailId"`
}

type WebAppPolicy struct {
	PolicyPull         bool `json:"policyPull"`
	PolicyPullInterval int  `json:"policyPullInterval"`
	ApplicationInfo    struct {
		Name    string   `json:"name"`
		Version string   `json:"version"`
		Tags    []string `json:"tags"`
	} `json:"applicationInfo"`
	VulnerabilityScan struct {
		Enabled bool `json:"enabled"`
		CveScan struct {
			Enabled                     bool `json:"enabled"`
			EnableEnvScan               bool `json:"enableEnvScan"`
			CveDefinitionUpdateInterval int  `json:"cveDefinitionUpdateInterval"`
		} `json:"cveScan"`
		IastScan struct {
			Enabled                  bool `json:"enabled"`
			ReportGenerationInterval int  `json:"reportGenerationInterval"`
			Probing                  struct {
				Interval  int `json:"interval"`
				BatchSize int `json:"batchSize"`
			} `json:"probing"`
			ReportServerPort   int  `json:"reportServerPort"`
			ReportServerEnable bool `json:"reportServerEnable"`
		} `json:"iastScan"`
	} `json:"vulnerabilityScan"`
	ProtectionMode struct {
		Enabled    bool `json:"enabled"`
		IPBlocking struct {
			Enabled            bool `json:"enabled"`
			AttackerIPBlocking bool `json:"attackerIpBlocking"`
			IPDetectViaXFF     bool `json:"ipDetectViaXFF"`
			Timeout            int  `json:"timeout"`
		} `json:"ipBlocking"`
		APIBlocking struct {
			Enabled                    bool `json:"enabled"`
			ProtectAllApis             bool `json:"protectAllApis"`
			ProtectKnownVulnerableApis bool `json:"protectKnownVulnerableApis"`
			ProtectAttackedApis        bool `json:"protectAttackedApis"`
		} `json:"apiBlocking"`
	} `json:"protectionMode"`
	SendCompleteStackTrace    bool             `json:"sendCompleteStackTrace"`
	EnableHTTPRequestPrinting bool             `json:"enableHTTPRequestPrinting"`
	PolicyParameters          PolicyParameters `json:"policyParameters"`
	Version                   string           `json:"version"`
	LogLevel                  string           `json:"logLevel"`
}
type PolicyParameters struct {
	AllowedIps      []string `json:"allowedIps"`
	BlockedIps      []string `json:"blockedIps"`
	AllowedApis     []string `json:"allowedApis"`
	BlockedApis     []string `json:"blockedApis"`
	AllowedRequests []string `json:"allowedRequests"`
}

type CveScanVersion struct {
	ID                           string `json:"id"`
	Platform                     string `json:"platform"`
	LatestServiceVersion         string `json:"latestServiceVersion"`
	LatestServiceSHA256          string `json:"latestServiceSHA256"`
	LatestProcessedServiceSHA256 string `json:"latestProcessedServiceSHA256"`
	LastServiceVersion           string `json:"lastServiceVersion"`
	LastServiceSHA256            string `json:"lastServiceSHA256"`
	LastProcessedServiceSHA256   string `json:"lastProcessedServiceSHA256"`
	Arch                         string `json:"arch"`
	ProcessedSaveName            string `json:"processedSaveName"`
}

type AppLevelConfig struct {
	K2ServiceInfo K2ServiceInfo `yaml:"k2ServiceInfo"`
	CustomerInfo  CustomerInfo  `yaml:"customerInfo"`
}

type GlobalPolicy struct {
	Version             string   `json:"version"`
	Timestamp           int64    `json:"timestamp"`
	LastUpdateTimestamp int64    `json:"lastUpdateTimestamp"`
	PolicyPullInterval  int      `json:"policyPullInterval"`
	AttackerIPTimeout   int      `json:"attackerIpTimeout"`
	AllowedIps          []string `json:"allowedIps"`
	BlockedIps          []string `json:"blockedIps"`
	AllowedApis         []string `json:"allowedApis"`
	BlockedApis         []string `json:"blockedApis"`
	AllowedRequests     []string `json:"allowedRequests"`
	LastFetchTime       int      `json:"lastFetchTime"`
	CustomerID          int      `json:"customerId"`
}
