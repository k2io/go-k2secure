// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_policy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-co-op/gocron"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2estclient "github.com/k2io/go-k2secure/v2/internal/k2secure_restclient"
	"github.com/k2io/go-k2secure/v2/k2secure_event"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var (
	fetcherJob *gocron.Job
	logger     = logging.GetLogger("policyFetcher")
	skipFirst  = false
	initlogs   = true
)

const jobTag = "policyFetcher"

func SchedulePolicyFetch(scheduleInterval int) {
	if scheduleInterval > 0 {
		logger.Infoln("Scheduling policy fetch every ", scheduleInterval, " Second")
		if fetcherJob != nil && fetcherJob.NextRun().Sub(time.Now()).Seconds() < float64(scheduleInterval) {
			fetcherJob, _ = k2i.TaskScheduler().Job(fetcherJob).Every(fmt.Sprintf("%ds", scheduleInterval)).Update()
		} else {
			UnschedulePolicyFetch()
			skipFirst = true
			fetcherJob, _ = k2i.TaskScheduler().Every(fmt.Sprintf("%ds", scheduleInterval)).Tag(jobTag).SingletonMode().Do(SendPolicyFetchRequest)
		}
	} else {
		UnschedulePolicyFetch()
	}

}

func UnschedulePolicyFetch() {
	if fetcherJob != nil {
		logger.Infoln("Stopping policy fetch schedule")
		k2i.TaskScheduler().RemoveByTag(jobTag)
		fetcherJob = nil
	}
}

func SendPolicyFetchRequest() {
	if skipFirst {
		skipFirst = false
		return
	}
	K2_AGENT_POLICY_PATH = filepath.Join(k2i.APPLICATION_POLICY, "lc-policy.yaml")
	logger.Infoln("Requesting policy")
	//_ = eventSender.SendMessage(PolicyFetchCommand().String())
	policy, responce, err := k2estclient.GetAgentPolicy(k2i.Info.EnvironmentInfo.GroupName, k2i.Info.AgentInfo.K2resource, k2i.Info.ApplicationInfo.AppUUID, k2i.Info.CustomerInfo.ApiAccessorToken, strconv.Itoa(k2i.Info.CustomerInfo.CustomerId))
	if err != nil {
		logger.WithError(err).Infoln("Agent Policy fetch failed")
		return
	}

	if policy.Version == "" {
		logger.Errorln("Policy Version should not be an empty string")
		return
	}
	if initlogs {
		logging.PrintInitlog(responce, "POLICY")
		initlogs = false
	}
	if policy.Version != k2i.Info.GlobalData.Version {
		if !ValidatePolicy(policy) {
			logger.Errorln("Failed to apply Agent Policy due to schema validatation")
			return
		}
		updateGlobalConf(policy)
		k2secure_event.SendApplicationInfo()
		err = writeAgentPolicy(policy)
		logger.Debugln("NEW CONFIG :", policy)
		if err == nil {
			logger.Infoln("Agent policy updated")
		} else {
			logger.Errorln("Agent policy update failed")
			return
		}
	} else {
		logger.Debugln("Application running with same policy version ", policy)
	}
}
