// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_policy

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-co-op/gocron"
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2estclient "github.com/k2io/go-k2secure/v2/internal/k2secure_restclient"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var (
	globalFetcherJob *gocron.Job
	globalSkipFirst  = false
)

const globalJobTag = "globalPolicyFetcher"

func scheduleGlobalPolicyFetch(scheduleInterval int) {
	if scheduleInterval > 0 {
		logger.Infoln("Scheduling policy fetch every ", scheduleInterval, " Second")
		if globalFetcherJob != nil && globalFetcherJob.NextRun().Sub(time.Now()).Minutes() < float64(scheduleInterval) {
			globalFetcherJob, _ = k2i.TaskScheduler().Job(globalFetcherJob).Every(fmt.Sprintf("%dm", scheduleInterval)).Update()
		} else {
			UnscheduleGlobalPolicyFetch()
			globalSkipFirst = true
			globalFetcherJob, _ = k2i.TaskScheduler().Every(fmt.Sprintf("%dm", scheduleInterval)).Tag(globalJobTag).SingletonMode().Do(SendGlobalPolicyFetchRequest)
		}
	} else {
		UnscheduleGlobalPolicyFetch()
	}

}

func UnscheduleGlobalPolicyFetch() {
	if globalFetcherJob != nil {
		logger.Infoln("Stopping Global policy fetch schedule")
		k2i.TaskScheduler().RemoveByTag(globalJobTag)
		globalFetcherJob = nil
	}
}

func SendGlobalPolicyFetchRequest() {
	fmt.Println("Global policy fetch started")
	if globalSkipFirst {
		globalSkipFirst = false
		return
	}
	policy, res, err := k2estclient.GetGlobalPolicy(k2i.Info.AgentInfo.K2resource, k2i.Info.CustomerInfo.ApiAccessorToken, strconv.Itoa(k2i.Info.CustomerInfo.CustomerId), k2i.Info.GlobalPolicy.Version)
	fmt.Println("Global policy response", res, err)
	if err != nil {
		logger.WithError(err).Infoln("Agent Global Policy fetch failed")
		return
	}
	if policy.Version == "" {
		logger.Errorln("GlobalPolicy Version should not be an empty string")
		return
	}
	if policy.Version != k2i.Info.GlobalPolicy.Version {
		updateGlobalPolicy(policy)
		logger.Debugln("NEW Global Policy :", policy)
	} else {
		logger.Debugln("Application running with same GlobalPolicy version ", policy)
	}
}

func updateGlobalPolicy(policy k2models.GlobalPolicy) {
	if policy.PolicyPullInterval != k2i.Info.GlobalPolicy.PolicyPullInterval {
		scheduleGlobalPolicyFetch(policy.PolicyPullInterval)
	}
	k2i.Info.GlobalPolicy = policy
}

func UpdateGlobalPolicyByControlCommand(policy k2models.K2Blocking) {
	logger.Debugln("NEW Global Policy :", policy)
	k2i.Info.GlobalPolicy.Version = policy.Version
	k2i.Info.GlobalPolicy.Timestamp = policy.Timestamp
	k2i.Info.GlobalPolicy.LastUpdateTimestamp = policy.LastUpdateTimestamp
	k2i.Info.GlobalPolicy.AttackerIPTimeout = policy.AttackerIPTimeout
	k2i.Info.GlobalPolicy.AllowedIps = policy.AllowedIps
	k2i.Info.GlobalPolicy.BlockedIps = policy.BlockedIps
	k2i.Info.GlobalPolicy.AllowedApis = policy.AllowedApis
	k2i.Info.GlobalPolicy.BlockedApis = policy.BlockedApis
	k2i.Info.GlobalPolicy.AllowedRequests = policy.AllowedRequests
	k2i.Info.GlobalPolicy.LastFetchTime = policy.LastFetchTime
	if policy.PolicyPullInterval != k2i.Info.GlobalPolicy.PolicyPullInterval {
		scheduleGlobalPolicyFetch(policy.PolicyPullInterval)
	}
	k2i.Info.GlobalPolicy.PolicyPullInterval = policy.PolicyPullInterval
}
