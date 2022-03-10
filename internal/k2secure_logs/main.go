// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_logs

import (
	"fmt"
)

//TODO update this file for centralized Logs
var logger = GetLogger("hookingLog")
var initlogs = InitLogger()

func IsHooked(name string, e error) {
	if e != nil {
		print := fmt.Sprintf("[%s]: %s", "INSTRUMENTATION", "Not able to hook function")
		logger.WithField("functionName", name).WithField("error", e.Error()).Errorln("Not able to hook function")
		initlogs.WithField("functionName", name).WithField("error", e.Error()).Errorln(print)
	} else {
		print := fmt.Sprintf("[%s]: %s", "INSTRUMENTATION", "Function successfully hooked")
		logger.WithField("functionName", name).Infoln("Function successfully hooked")
		initlogs.WithField("functionName", name).Infoln(print)
	}
}
func Info(name ...string) {

}
func Debug(name ...string) {

}
func Error(name string, e error) {

}
