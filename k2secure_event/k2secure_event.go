// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_event

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"errors"

	"github.com/go-co-op/gocron"
	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2impl "github.com/k2io/go-k2secure/v2/k2secure_impl"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

const (
	language       = "GOLANG"
	maxConnsPerMsg = 40
)

var (
	protectedDb             = []string{"SQLITE3", "MYSQL", "MONGO", "POSTGRES"}
	protectedVulnerabilties = []string{"FILE_ACCESS", "SQLI", "RCE", "RCI", "REVERSE_SHELL", "NOSQLI", "SSRF", "LDAP", "XPATH", "DESERIALIZATION"}
	lastHC                  = time.Now()
	statsDuration           = time.Duration(120) * time.Minute //2 hours
	lastStats               = time.Now()
	initlogs                = true
)

var (
	hcJob *gocron.Job
)

const jobTag = "hcjob"

func InitSc() {
	if hcJob == nil {
		hcJob, _ = k2i.TaskScheduler().Every(fmt.Sprintf("5m")).Tag(jobTag).SingletonMode().Do(K2HealthCheck)
	}
}
func K2HealthCheck() {
	if !isWsStarted() {
		return
	}
	var tmp_info k2models.LAhealthcheck
	tmp_info.CollectorVersion = k2utils.CollectorVersion
	tmp_info.JSONName = "LAhealthcheck"
	tmp_info.JSONVersion = k2utils.JsonVersion
	tmp_info.CollectorType = k2utils.CollectorType
	tmp_info.Language = language
	tmp_info.BuildNumber = k2utils.BuildNumber
	tmp_info.Framework = ""
	tmp_info.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	tmp_info.ProtectedServer = k2i.Info.ApplicationInfo.ProtectedServer
	tmp_info.ProtectedDB = protectedDb
	tmp_info.ProtectedVulnerabilties = protectedVulnerabilties
	tmp_info.EventDropCount = k2i.Info.EventData.DropEventCount
	tmp_info.EventProcessed = k2i.Info.EventData.EventProcessCount
	tmp_info.EventSentCount = k2i.Info.EventData.EventCount
	tmp_info.HTTPRequestCount = k2i.Info.EventData.RequestCount
	tmp_info.GroupName = k2i.Info.EnvironmentInfo.GroupName
	tmp_info.NodeID = k2i.Info.EnvironmentInfo.NodeId
	tmp_info.CustomerID = k2i.Info.CustomerInfo.CustomerId
	tmp_info.EmailID = k2i.Info.CustomerInfo.EmailId
	tmp_info.PolicyVersion = k2i.Info.GlobalData.Version

	_, err1 := sendEvent(tmp_info)
	if err1 != nil {
		logger.WithField("errorMsg", err1).Errorln("Error during sending the event")
		return
	}
	k2i.Info.EventData.EventCount = 0
	k2i.Info.EventData.DropEventCount = 0
	k2i.Info.EventData.RequestCount = 0
	k2i.Info.EventData.EventProcessCount = 0
	if k2i.Info.SecureWS != nil {
		(k2i.Info.SecureWS).UploadLogOnRotationWS()
	}
	K2HttpConnectionStats()
	K2HttpConnectionStatsCached()
}

func K2HttpConnectionStats() {

	if !isWsStarted() {
		return
	}
	var tmp_info k2models.HttpConnectionStat

	tmp_info.CollectorVersion = k2utils.CollectorVersion
	tmp_info.JSONName = "http-connection-stat"
	tmp_info.JSONVersion = k2utils.JsonVersion
	tmp_info.CollectorType = k2utils.CollectorType
	tmp_info.Language = language
	tmp_info.BuildNumber = k2utils.BuildNumber
	tmp_info.Framework = ""
	tmp_info.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	tmp_info.IsCached = false
	tmp_info.GroupName = k2i.Info.EnvironmentInfo.GroupName
	tmp_info.NodeID = k2i.Info.EnvironmentInfo.NodeId
	tmp_info.CustomerID = k2i.Info.CustomerInfo.CustomerId
	tmp_info.EmailID = k2i.Info.CustomerInfo.EmailId
	tmp_info.PolicyVersion = k2i.Info.GlobalData.Version

	hcm := k2impl.GetHttpConnectionsJSON(false)
	if len(hcm) == 0 {
		logger.Debugln("nothing to send - HttpConnStats ...")
		return
	}

	dev := len(hcm) / maxConnsPerMsg
	last := 0
	for i := 1; i <= dev; i = i + 1 {
		n := maxConnsPerMsg * i
		if n > len(hcm) {
			n = len(hcm)
		}
		tmp_info.HTTPConnections = hcm[last:n]
		last = n
		_, err1 := sendEvent(tmp_info)
		if err1 != nil {
			logger.WithField("errorMsg", err1).Errorln("Error during sending the event")
			return
		}
	}

	if last <= len(hcm)-1 {
		tmp_info.HTTPConnections = hcm[last:]
		_, err1 := sendEvent(tmp_info)
		if err1 != nil {
			logger.WithField("errorMsg", err1).Errorln("Error during sending the event")
			return
		}
	}
}
func K2HttpConnectionStatsCached() {

	t := time.Now()
	if t.Sub(lastStats) < statsDuration {
		return
	}
	lastStats = t
	if !isWsStarted() {
		return
	}
	var tmp_info k2models.HttpConnectionStat

	tmp_info.CollectorVersion = k2utils.CollectorVersion
	tmp_info.JSONName = "http-connection-stat"
	tmp_info.JSONVersion = k2utils.JsonVersion
	tmp_info.CollectorType = k2utils.CollectorType
	tmp_info.Language = language
	tmp_info.BuildNumber = k2utils.BuildNumber
	tmp_info.Framework = ""
	tmp_info.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	tmp_info.IsCached = true
	tmp_info.GroupName = k2i.Info.EnvironmentInfo.GroupName
	tmp_info.NodeID = k2i.Info.EnvironmentInfo.NodeId
	tmp_info.CustomerID = k2i.Info.CustomerInfo.CustomerId
	tmp_info.EmailID = k2i.Info.CustomerInfo.EmailId
	tmp_info.PolicyVersion = k2i.Info.GlobalData.Version

	hcm := k2impl.GetHttpConnectionsJSON(true)
	if len(hcm) == 0 {
		logger.Debugln("nothing to send - HttpConnStats ...")
		return
	}
	dev := len(hcm) / maxConnsPerMsg
	last := 0
	for i := 1; i <= dev; i = i + 1 {
		n := maxConnsPerMsg * i
		if n > len(hcm) {
			n = len(hcm)
		}
		tmp_info.HTTPConnections = hcm[last:n]
		last = n
		_, err1 := sendEvent(tmp_info)
		if err1 != nil {
			logger.WithField("errorMsg", err1).Errorln("Error during sending the event")
			return
		}
	}

	if last <= len(hcm)-1 {
		tmp_info.HTTPConnections = hcm[last:]
		_, err1 := sendEvent(tmp_info)
		if err1 != nil {
			logger.WithField("errorMsg", err1).Errorln("Error during sending the event")
			return
		}
	}

}
func SendApplicationInfo() {
	if initlogs {
		logging.NewStage("5", "APP_INFO", "Gathering application info for current process")
	}
	_ = K2NewProcess()

	var tmp_info k2models.ApplicationInfo

	hostname, _ := os.Hostname()

	eventInfo := map[string]interface{}{
		"name":              hostname,
		"creationTimestamp": time.Now().Unix() * 1000,
		"ipAddress":         k2i.Info.EnvironmentInfo.CollectorIp,
	}

	identifier := map[string]interface{}{
		"nodeName":    k2i.Info.EnvironmentInfo.NodeName,
		"nodeId":      k2i.Info.EnvironmentInfo.NodeId,
		"nodeIp":      k2i.Info.EnvironmentInfo.NodeIp,
		"collectorIp": k2i.Info.EnvironmentInfo.CollectorIp,
		"kind":        k2i.Info.EnvironmentInfo.RunningEnv,
		"eventInfo":   eventInfo,
	}
	if k2i.Info.EnvironmentInfo.RunningEnv == "HOST" {
		identifier["id"] = k2i.Info.EnvironmentInfo.NodeId
		identifier["os"] = k2i.Info.EnvironmentInfo.Goos
		identifier["arch"] = k2i.Info.EnvironmentInfo.Goarch
		identifier["ipAdress"] = k2i.Info.EnvironmentInfo.CollectorIp
		k2i.Info.EnvironmentInfo.ID = k2i.Info.EnvironmentInfo.NodeId
	} else if k2i.Info.EnvironmentInfo.RunningEnv == "CONTAINER" {
		identifier["id"] = k2i.Info.EnvironmentInfo.ContainerId
		identifier["ipAdress"] = k2i.Info.EnvironmentInfo.CollectorIp
		k2i.Info.EnvironmentInfo.ID = k2i.Info.EnvironmentInfo.ContainerId
	} else if k2i.Info.EnvironmentInfo.RunningEnv == "KUBERNETES" {
		identifier["id"] = k2i.Info.EnvironmentInfo.PodId
		identifier["ipAdress"] = k2i.Info.EnvironmentInfo.CollectorIp
		identifier["namespace"] = k2i.Info.EnvironmentInfo.Namespaces
		k2i.Info.EnvironmentInfo.ID = k2i.Info.EnvironmentInfo.PodId

	}

	tmp_info.Identifier = identifier
	// configer deployedApplications and serverInfo

	bin := filepath.Base(k2i.Info.ApplicationInfo.Cmd)

	if k2i.Info.ApplicationInfo.Ports != nil && len(k2i.Info.ApplicationInfo.Ports) > 0 {
		k2i.Info.ApplicationInfo.ContextPath = bin + ":" + strconv.Itoa(k2i.Info.ApplicationInfo.Ports[0]) + "/"
	} else {
		k2i.Info.ApplicationInfo.ContextPath = bin
	}
	applicationPort := k2i.Info.ApplicationInfo.Ports
	if applicationPort == nil {
		applicationPort = make([]int, 0)
		applicationPort = append(applicationPort, -1)
	}
	deployedApplications := map[string]interface{}{
		"deployedPath": k2i.Info.EnvironmentInfo.Wd,
		"appName":      bin,
		"sha256":       k2i.Info.ApplicationInfo.Sha256,
		"size":         k2i.Info.ApplicationInfo.Size,
		"contextPath":  k2i.Info.ApplicationInfo.ContextPath,
		"isEmbedded":   false,
		"ports":        applicationPort,
	}

	var arg11 []interface{}
	arg11 = append(arg11, deployedApplications)

	serverName := strings.Join(k2i.Info.ApplicationInfo.ServerName, ",")
	// if serverName != "GRPC" {
	// 	serverName = "net/http"
	// }

	serverInfo := map[string]interface{}{
		"name":                 serverName,
		"deployedApplications": arg11,
	}

	tmp_info.ServerInfo = serverInfo

	tmp_info.GroupName = k2i.Info.EnvironmentInfo.GroupName
	tmp_info.NodeID = k2i.Info.EnvironmentInfo.NodeId
	tmp_info.CustomerID = k2i.Info.CustomerInfo.CustomerId
	tmp_info.EmailID = k2i.Info.CustomerInfo.EmailId

	tmp_info.CollectorVersion = k2utils.CollectorVersion
	tmp_info.JSONName = "applicationinfo"
	tmp_info.JSONVersion = k2utils.JsonVersion
	tmp_info.CollectorType = k2utils.CollectorType
	tmp_info.Language = language
	tmp_info.Framework = ""
	tmp_info.BuildNumber = k2utils.BuildNumber
	tmp_info.Sha256 = k2i.Info.ApplicationInfo.Sha256
	tmp_info.Pid = k2i.Info.ApplicationInfo.Pid

	tmp_info.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	tmp_info.Cmdline = k2i.Info.ApplicationInfo.Cmdline
	tmp_info.StartTime = k2i.Info.ApplicationInfo.Starttimestr
	tmp_info.RunCommand = strings.Join(k2i.Info.ApplicationInfo.Cmdline, " ")
	tmp_info.UserDir = k2i.Info.EnvironmentInfo.Wd
	tmp_info.BinaryName = bin
	tmp_info.OsArch = k2i.Info.EnvironmentInfo.Goarch
	tmp_info.OsName = k2i.Info.EnvironmentInfo.Goos
	tmp_info.BinaryPath = k2i.Info.ApplicationInfo.BinaryPath
	tmp_info.AgentAttachmentType = "STATIC"
	tmp_info.PolicyVersion = k2i.Info.GlobalData.Version
	tmp_info.UserProvidedApplicationInfo = getUserProvidedApplicationInfo()

	appinfo, err1 := sendEvent(tmp_info)
	if err1 != nil {

		logger.WithField("errorMsg", err1).Errorln("Error during sending the application info event")
		if initlogs {
			logging.PrintInitErrolog("Error while Sending ApplicationInfo "+err1.Error(), "APP_INFO")
		}
		return
	} else {
		if initlogs {
			logging.PrintInitlog("Application info generated  "+appinfo, "APP_INFO")
		}
	}
	if initlogs {
		logging.EndStage("5", "APP_INFO")
		initlogs = false
	}

}

func SendFuzzFailEvent(fuzzHeader string) {
	var fuzzFailEvent k2models.FuzzFailBean
	fuzzFailEvent.CollectorVersion = k2utils.CollectorVersion
	fuzzFailEvent.JSONName = "fuzzfail"
	fuzzFailEvent.JSONVersion = k2utils.JsonVersion
	fuzzFailEvent.Language = language
	fuzzFailEvent.Framework = ""
	fuzzFailEvent.CollectorType = k2utils.CollectorType
	fuzzFailEvent.FuzzHeader = fuzzHeader
	fuzzFailEvent.BuildNumber = k2utils.BuildNumber
	fuzzFailEvent.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	fuzzFailEvent.GroupName = k2i.Info.EnvironmentInfo.GroupName
	fuzzFailEvent.NodeID = k2i.Info.EnvironmentInfo.NodeId
	fuzzFailEvent.CustomerID = k2i.Info.CustomerInfo.CustomerId
	fuzzFailEvent.EmailID = k2i.Info.CustomerInfo.EmailId
	fuzzFailEvent.PolicyVersion = k2i.Info.GlobalData.Version

	_, err1 := sendEvent(fuzzFailEvent)
	if err1 != nil {
		logger.WithField("errorMsg", err1).Errorln("Error during sending the fuzz fail event")
		return
	}
}

func SendVulnerableEvent(req *k2models.Info_req, category string, args interface{}) {
	//TODO
}

func sendEvent(event interface{}) (string, error) {
	event_json, err1 := json.Marshal(event)
	if err1 != nil {
		logger.WithField("event", string(event_json)).Errorln("Error unmarshall JSON before send")
		return "", err1
	}
	// logger.WithField("event", string(event_json)).Infoln("k2startup: ready to send") // not using this as this is escaping the event json
	logger.Infoln("k2startup : ready to send : ", string(event_json))
	if k2i.Info.SecureWS != nil {
		(k2i.Info.SecureWS).Send([]byte(string(event_json)))
		return string(event_json), nil
	} else {
		logger.Errorln("k2secure websocket not configured. not sending.")
		return "", errors.New("k2secure websocket not configured or not sending")
	}
}

func isWsStarted() bool {
	if k2i.Info == nil {
		return false
	}
	if k2i.Info.SecureWS == nil {
		return false
	}
	return true
}

func getUserProvidedApplicationInfo() k2models.UserProvidedApplicationInfo {
	name := k2i.Info.EnvironmentInfo.UserAppName
	version := k2i.Info.EnvironmentInfo.UserAppVersion
	tags := k2i.Info.EnvironmentInfo.UserAppTags
	if name == "" {
		name = k2i.Info.GlobalData.ApplicationInfo.Name
	}
	if version == "" {
		version = k2i.Info.GlobalData.ApplicationInfo.Version
	}
	var tag []string
	if tags == "" {
		tag = k2i.Info.GlobalData.ApplicationInfo.Tags
	} else {
		tag = strings.Split(tags, ",")
	}
	var tmp_info k2models.UserProvidedApplicationInfo
	tmp_info.Name = name
	tmp_info.Version = version
	tmp_info.Tags = tag
	return tmp_info
}
