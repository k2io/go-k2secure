// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_policy

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2restclient "github.com/k2io/go-k2secure/v2/internal/k2secure_restclient"
	k2scan "github.com/k2io/go-k2secure/v2/k2secure_cvescan"
	"github.com/k2io/go-k2secure/v2/k2secure_event"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
	"gopkg.in/yaml.v2"
)

var K2_AGENT_POLICY_PATH = ""

func ReadAgentPolicy() (policy k2models.WebAppPolicy, err error) {
	var data []byte

	data, err = ioutil.ReadFile(K2_AGENT_POLICY_PATH)
	if err != nil {
		logger.WithError(err).Errorln("Error while reading agent policy")
		return
	}

	err = yaml.Unmarshal(data, &policy)
	if err != nil {
		logger.WithError(err).Errorln("Error while unmarshalling agent policy")
		return
	}
	if policy.Version == "" {
		logger.Errorln("Policy Version should not be an empty string")
		return
	}
	if policy.Version != k2i.Info.GlobalData.Version {
		if !ValidatePolicy(policy) {
			logger.Errorln("Failed to apply Agent Policy due to schema validatation")
			return
		}
		updateGlobalConf(policy)
		k2secure_event.SendApplicationInfo()
		policy_json, err1 := json.Marshal(policy)
		if err1 != nil {
			logger.Errorln("Error while marshalling agent policy")
			return
		}
		err := k2restclient.PostAgentPolicy(k2i.Info.EnvironmentInfo.GroupName, k2i.Info.AgentInfo.K2resource, k2i.Info.ApplicationInfo.AppUUID, k2i.Info.CustomerInfo.ApiAccessorToken, strconv.Itoa(k2i.Info.CustomerInfo.CustomerId), string(policy_json))
		if err != nil {
			logger.WithError(err)
		}
	} else {
		logger.Debugln("Application running with same policy version ", policy)
	}
	return
}

func writeAgentPolicy(policy k2models.WebAppPolicy) (err error) {
	var data []byte
	data, err = yaml.Marshal(&policy)
	if err != nil {
		logger.WithError(err).Errorln("Error while marshalling agent policy")
		return
	}
	err = writeAgentPolicyData(data)
	return
}
func writeAgentPolicyData(data []byte) (err error) {
	err = os.MkdirAll(filepath.Dir(K2_AGENT_POLICY_PATH), os.ModePerm)
	if err != nil {
		logger.WithError(err).WithField("path", filepath.Dir(K2_AGENT_POLICY_PATH)).Errorln("Error while creating agent policy dir")
		return
	}
	err = ioutil.WriteFile(K2_AGENT_POLICY_PATH, data, os.ModePerm)
	if err != nil {
		logger.WithError(err).WithField("path", K2_AGENT_POLICY_PATH).Errorln("Error while writing agent policy")
		return
	}
	return
}
func updateGlobalConf(policy k2models.WebAppPolicy) {
	if policy.PolicyPull {
		if k2i.Info.GlobalData.PolicyPull {
			if policy.PolicyPullInterval != k2i.Info.GlobalData.PolicyPullInterval {
				SchedulePolicyFetch(policy.PolicyPullInterval)
			}
		} else {
			SchedulePolicyFetch(policy.PolicyPullInterval)
		}
	} else {
		UnschedulePolicyFetch()
	}

	if policy.VulnerabilityScan.Enabled && policy.VulnerabilityScan.CveScan.Enabled {
		if k2i.Info.GlobalData.VulnerabilityScan.Enabled && k2i.Info.GlobalData.VulnerabilityScan.CveScan.Enabled {
			if policy.VulnerabilityScan.CveScan.EnableEnvScan && !k2i.Info.GlobalData.VulnerabilityScan.CveScan.EnableEnvScan {
				logger.Infoln("Run only env scan")
				k2scan.RunScanRequest(false, true, true)
				//k2scan.RunCveScan(false, true)
			}
			if policy.VulnerabilityScan.CveScan.EnableEnvScan {
				k2scan.ScheduleCVEScan(policy.VulnerabilityScan.CveScan.CveDefinitionUpdateInterval, k2i.Info.GlobalData.VulnerabilityScan.CveScan.CveDefinitionUpdateInterval, true)
			} else {
				k2scan.ScheduleCVEScan(policy.VulnerabilityScan.CveScan.CveDefinitionUpdateInterval, k2i.Info.GlobalData.VulnerabilityScan.CveScan.CveDefinitionUpdateInterval, false)
			}
		} else {
			if policy.VulnerabilityScan.CveScan.EnableEnvScan {
				k2scan.ScheduleCVEScan(policy.VulnerabilityScan.CveScan.CveDefinitionUpdateInterval, 0, true)
			} else {
				k2scan.ScheduleCVEScan(policy.VulnerabilityScan.CveScan.CveDefinitionUpdateInterval, 0, false)
			}
		}
	} else {
		k2scan.UnscheduleCVEFetch()
	}

	k2i.Info.GlobalData = policy
	logging.SetLogLevel(policy.LogLevel)
}
