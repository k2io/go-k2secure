// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_event

import (
	"fmt"
	"path/filepath"

	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"

	k2map "github.com/k2io/go-k2secure/v2/internal/k2secure_hashmap"
	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2model "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2Utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2impl "github.com/k2io/go-k2secure/v2/k2secure_impl"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
	"github.com/sirupsen/logrus"
)

var (
	logger       *logrus.Entry
	disableagent = false
)

var nullHook = false

func SetNullHook() {
	nullHook = true
}

func K2NewProcess() bool {
	if k2i.Info == nil {
		return false
	}
	p := strconv.Itoa(syscall.Getpid())
	if k2i.Info.ApplicationInfo.Pid != p {
		logger.Infoln("new Process found - TODO K2 reinitialize")
		starttime := time.Now().Unix() * 1000
		k2i.Info.ApplicationInfo.Starttimestr = k2Utils.Int64ToString(starttime)
		k2i.Info.ApplicationInfo.Pid = p
		return true
	}
	return false
}

func InitWS(a k2i.SecureWSiface) {
	if k2i.Info == nil {
		logger.Infoln("calling doInit - Info is nil")
		initK2Envirement()
	}
	if os.Getenv("K2_DISABLE") == "true" {
		k2i.SetDropHooksRequest()
		logger.Infoln("K2_DISABLE Hooks - disable all hooks")
	} else if nullHook {
		logger.Infoln("NullHook - disable all event sends")
	} else if k2i.Info != nil {
		if !k2i.Info.AgentInfo.SecureWSready {
			logger.Infoln("k2secure WS initialization done")
			k2i.Info.SecureWS = a
			k2i.Info.AgentInfo.SecureWSready = true
		}
	}
	InitSc()
}
func UpdateAgentInfoFromCC(cid, nip, nid, nname string) {
	id, _ := strconv.Atoi(cid)
	k2i.Info.CustomerInfo.CustomerId = id
	k2i.Info.EnvironmentInfo.NodeIp = nip
	k2i.Info.EnvironmentInfo.NodeId = nid
}

func initBaseAppInfo() {
	k2i.Info.ApplicationInfo.Pid = k2Utils.IntToString(os.Getpid())
	binaryPath, err := os.Executable()
	if err != nil {
		binaryPath = os.Args[0]
	}
	k2i.Info.ApplicationInfo.BinaryPath = binaryPath
	k2i.Info.ApplicationInfo.Sha256 = k2Utils.CalculateSha256(binaryPath)
	k2i.Info.ApplicationInfo.Cmd = os.Args[0]
	k2i.Info.ApplicationInfo.Cmdline = os.Args[0:]
	startTime := time.Now().Unix() * 1000
	k2i.Info.ApplicationInfo.Starttimestr = k2Utils.Int64ToString(startTime)
	k2i.Info.ApplicationInfo.Size = k2Utils.CalculateFileSize(binaryPath)

}

func initWithNodeLevelConfFile() bool {
	confFilePath := k2i.Info.EnvironmentInfo.NlcPath
	if confFilePath == "" {
		confFilePath = filepath.Join(k2i.CONFIG_PATH, "node-level-config.yaml") //TODO
	}
	if !k2Utils.IsFileExist(confFilePath) {
		logging.PrintWarnlog("Node level configuration was not found or incorrect on path "+confFilePath, "ENV")
		return false
	}
	nodeLevelConfig := new(k2model.NodeLevelConfig)
	err := k2Utils.ReadNodeLevelConfig(confFilePath, nodeLevelConfig)
	if err == nil {
		logging.PrintInitlog("Node Level Configuration loaded : "+k2Utils.StructToString(nodeLevelConfig), "ENV")
		k2i.Info.EnvironmentInfo.NodeName = nodeLevelConfig.NodeName
		k2i.Info.EnvironmentInfo.NodeIp = nodeLevelConfig.NodeIp
		k2i.Info.EnvironmentInfo.NodeId = nodeLevelConfig.NodeId
		k2i.Info.EnvironmentInfo.NodeGroupTags = nodeLevelConfig.NodeGroupTags
		k2i.Info.AgentInfo.K2validator = nodeLevelConfig.K2ServiceInfo.ValidatorServiceEndpointURL
		k2i.Info.AgentInfo.K2resource = nodeLevelConfig.K2ServiceInfo.ResourceServiceEndpointURL
		k2i.Info.CustomerInfo = nodeLevelConfig.CustomerInfo
		return true
	} else {
		logger.Errorln(err)
		logging.PrintInitErrolog("Error while parsing Node Level Configuration "+err.Error(), "ENV")
		return false
	}
}

func initWithAppLevelConfFile() bool {
	confFilePath := k2i.Info.EnvironmentInfo.AlcPath
	if confFilePath == "" {
		confFilePath = filepath.Join(k2i.CONFIG_PATH, "app-level-config.yaml") //TODO
	}
	if !k2Utils.IsFileExist(confFilePath) {
		logger.Warnln("K2 app-level-config file is missing")
		logging.PrintWarnlog("Application Level Configuration was not provided", "ENV")
		return false
	}
	appLevelConfig := new(k2model.AppLevelConfig)
	err := k2Utils.ReadAppLevelConfig(confFilePath, appLevelConfig)
	if err == nil {
		logging.PrintInitlog("Application Level Configuration loaded : "+k2Utils.StructToString(appLevelConfig), "ENV")
		k2i.Info.AgentInfo.K2validator = appLevelConfig.K2ServiceInfo.ValidatorServiceEndpointURL
		k2i.Info.AgentInfo.K2resource = appLevelConfig.K2ServiceInfo.ResourceServiceEndpointURL
		k2i.Info.CustomerInfo = appLevelConfig.CustomerInfo
		return true
	} else {
		logger.Errorln(err)
		logging.PrintInitErrolog("Error while parsing Application Level Configuration "+err.Error(), "ENV")
		return false

	}
}

func initK2Envirement() {
	if k2i.Info != nil {
		logger.Infoln("K2secure interface is already allocated")
		return
	}
	k2i.InitK2BaseInfo(true)
	k2i.Info.Secure = k2impl.K2secureimpl{}
	applicationUUID := k2Utils.GetUniqueUUID()
	k2i.Info.ApplicationInfo.AppUUID = applicationUUID
	k2_home := os.Getenv("K2_HOME")
	k2i.InitConst(k2_home, runtime.GOOS, applicationUUID)
	logging.Init_log(applicationUUID, k2i.LOG_FILE_PATH)
	logger = logging.GetLogger("Init")
	logger.Infoln("Application started with UUID : ", applicationUUID)
	pid := strconv.Itoa(syscall.Getpid())
	//readAllEnvVariables
	printlogs := fmt.Sprintf("K2 Go-lang collector attached to process: PID = %s, with generated applicationUID = %s by STATIC attachment", pid, applicationUUID)
	logging.NewStage("1", "PROTECTION", printlogs)
	logging.EndStage("1", "PROTECTION")
	logging.NewStage("2", "ENV", "Current environment variables")
	k2i.Info.EnvironmentInfo.NlcPath = os.Getenv("K2_AGENT_NODE_CONFIG")
	k2i.Info.EnvironmentInfo.AlcPath = os.Getenv("K2_AGENT_APP_CONFIG")
	k2i.Info.EnvironmentInfo.UserAppName = os.Getenv("K2_APP_NAME")
	k2i.Info.EnvironmentInfo.UserAppVersion = os.Getenv("K2_APP_VERSION")
	k2i.Info.EnvironmentInfo.UserAppTags = os.Getenv("K2_APP_TAGS")
	k2i.Info.EnvironmentInfo.GroupName = os.Getenv("K2_GROUP_NAME")
	k2i.Info.EnvironmentInfo.CollectorIp = k2Utils.FindIpAddress()
	k2i.Info.EnvironmentInfo.Wd = k2Utils.GetWorkingDir()
	k2i.Info.EnvironmentInfo.Goos = runtime.GOOS
	k2i.Info.EnvironmentInfo.Goarch = runtime.GOARCH
	k2i.Info.EnvironmentInfo.Gopath = k2Utils.GetGoPath()
	k2i.Info.EnvironmentInfo.Goroot = k2Utils.GetGoRoot()
	k2i.Info.EnvironmentInfo.Wd = k2Utils.GetWorkingDir()
	env_type, cid, err := k2Utils.GetContainerId()
	if err != nil {
		logger.Errorln(err)
	}
	if !env_type {
		k2i.Info.EnvironmentInfo.RunningEnv = "HOST"
	} else {
		k2i.Info.EnvironmentInfo.ContainerId = cid
		if !k2Utils.IsKubernetes() {
			k2i.Info.EnvironmentInfo.RunningEnv = "CONTAINER"
		} else {
			k2i.Info.EnvironmentInfo.RunningEnv = "KUBERNETES"
			k2i.Info.EnvironmentInfo.Namespaces = k2Utils.GetKubernetesNS()
			k2i.Info.EnvironmentInfo.PodId = k2Utils.GetPodId()
		}
	}

	logging.PrintInitlog("Current environment variables : "+k2Utils.StructToString(k2i.Info.EnvironmentInfo), "ENV")
	if k2i.Info.EnvironmentInfo.GroupName == "" {
		logger.Errorln("Policy group name should not be nill")
		logging.PrintInitErrolog("Disable K2 Go agent K2_GROUP_NAME env variable is missing", "ENV")
		disableagent = true
	}

	if !disableagent {
		nl := initWithNodeLevelConfFile()
		al := initWithAppLevelConfFile()
		if !nl {
			if k2i.Info.EnvironmentInfo.RunningEnv == "CONTAINER" || k2i.Info.EnvironmentInfo.RunningEnv == "HOST" || k2i.Info.EnvironmentInfo.RunningEnv == "KUBERNETES" {
				logging.PrintInitErrolog("Disable K2 Go agent Node level configuration is missing ", "ENV")
				disableagent = true
			} else {
				if !al {
					logging.PrintInitErrolog("Disable K2 Go agent App level configuration is missing ", "ENV")
					disableagent = true
				}
			}
		}
	}
	if !disableagent {
		initBaseAppInfo()
		k2map.InitSwapMap()
		k2i.Info.IsK2Disable = false
	} else {
		logger.Errorln("disable k2 agent ")

		k2i.Info.IsK2Disable = true
	}
	logging.EndStage("2", "ENV")
}

func init() {
	if k2Utils.CaseInsensitiveEquals(os.Getenv("K2_DISABLE"), "true") {
		fmt.Println("[K2-Go] Disable K2 Go agent due to K2_DISABLE environment variable set to true")
		k2i.InitK2BaseInfo(false)
		k2i.Info.IsK2Disable = true
		return
	}
	initK2Envirement()
}
