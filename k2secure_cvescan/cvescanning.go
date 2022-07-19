// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_cvescan

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-co-op/gocron"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2restclient "github.com/k2io/go-k2secure/v2/internal/k2secure_restclient"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var (
	cveJob          *gocron.Job
	logger          = logging.GetLogger("cveScanning")
	lastScanVersion = ""
	scanedFileName  = ""
	isEnv           = false
	interval        = 0
)

const jobTag = "cveScan"

func ScheduleCVEScan(scheduleInterval, lastScheduleInterval int, isEnvScan bool) {
	logger.Infoln("Scheduling CVE Scan every ", scheduleInterval, " minutes", " lastScheduleInterval ", lastScheduleInterval)
	isEnv = isEnvScan
	if scheduleInterval == lastScheduleInterval {
		return
	}
	if scheduleInterval > 0 {
		if cveJob != nil && cveJob.NextRun().Sub(time.Now()).Seconds() < float64(scheduleInterval) {
			cveJob, _ = k2i.TaskScheduler().Job(cveJob).Every(fmt.Sprintf("%dm", scheduleInterval)).Update()
		} else {
			UnscheduleCVEFetch()
			cveJob, _ = k2i.TaskScheduler().Every(fmt.Sprintf("%dm", scheduleInterval)).Tag(jobTag).SingletonMode().Do(cveScanRequest)
		}
	} else {
		UnscheduleCVEFetch()
	}
	interval = scheduleInterval
}

func UnscheduleCVEFetch() {
	if cveJob != nil {
		logger.Infoln("Stopping policy fetch schedule")
		k2i.TaskScheduler().RemoveByTag(jobTag)
		cveJob = nil
	}
}

func cveScanRequest() {
	RunScanRequest(true, isEnv, false)
}

func RunScanRequest(isAppScan, isEnvScan, force bool) {
	logger.Infoln("Cve scanning initiated")
	data, err := k2restclient.GetCVEVersion(k2i.Info.EnvironmentInfo.Goos, "x64", k2i.Info.AgentInfo.K2resource, k2i.Info.CustomerInfo.ApiAccessorToken, strconv.Itoa(k2i.Info.CustomerInfo.CustomerId))
	if err != nil {
		logger.WithError(err).Infoln("Cve Scan Version fetch failed")
		return
	}
	logger.Debugln("CVE scan latest version ", data.LatestServiceVersion)
	logger.Debugln("CVE scan last version ", lastScanVersion)
	if lastScanVersion != data.LatestServiceVersion {
		RunCveScan(isAppScan, isEnvScan, data.LatestServiceVersion, data.LatestProcessedServiceSHA256)
	} else {
		logger.Infoln("No need to download cve tar")
		if force {
			RunCveScan(isAppScan, isEnvScan, data.LatestServiceVersion, data.LatestProcessedServiceSHA256)
		}
	}
}
