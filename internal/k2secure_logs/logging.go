// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_logs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()
var initlog = logrus.New()
var LogfileAbsPath string
var disable = false

func Init_log(uuid, logFilepath string) {
	if log == nil {
		log = logrus.New()
	}
	syscall.Umask(0)
	os.MkdirAll(logFilepath, os.ModePerm)
	// log as JSON instead of the default ASCII formatter.
	//log.SetFormatter(&runtime.Formatter{ChildFormatter: &log.JSONFormatter{}, Line: true, Package: true})
	formatter := logrus.TextFormatter{
		ForceColors:     true,
		ForceQuote:      true,
		FullTimestamp:   true,
		TimestampFormat: "02-Jan-2006 15:04:05 MST",
		DisableSorting:  false,
		PadLevelText:    true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			return "", fmt.Sprintf(" %s:%d", filename, f.Line)
		},
	}
	log.SetFormatter(&formatter)
	log.SetReportCaller(true)
	pid := int64(os.Getpid())
	rotateFileHook, err, logFileName := NewRotateFileHook(RotateFileConfig{
		Filename:   filepath.Join(logFilepath, "k2_go_agent_"+strconv.FormatInt(pid, 10)+"_"+uuid+".log"),
		MaxSize:    10, // megabytes
		MaxBackups: 50,
		MaxAge:     2, //days
		Level:      logrus.TraceLevel,
		Formatter:  &formatter,
	})

	LogfileAbsPath = logFileName
	if err != nil {
		log.Errorln("Error during creating log file ", err)
	}
	log.SetOutput(ioutil.Discard) // if output not discarded, it will send to stdout, this does not impact log file created through rotate file hook
	// Only log the warning severity or above.
	if os.Getenv("K2_DEBUG_MODE") == "true" {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
	log.SetLevel(logrus.InfoLevel)
	log.AddHook(rotateFileHook)
	init_initLog(uuid, logFilepath)
}

func init_initLog(uuid, logFilepath string) {
	if initlog == nil {
		initlog = logrus.New()
	}

	// log as JSON instead of the default ASCII formatter.
	//log.SetFormatter(&runtime.Formatter{ChildFormatter: &log.JSONFormatter{}, Line: true, Package: true})
	formatter := logrus.TextFormatter{
		ForceColors:    true,
		ForceQuote:     false,
		FullTimestamp:  false,
		DisableSorting: false,
		PadLevelText:   false,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {

			return "", " "
		},
	}
	initlog.SetFormatter(&formatter)
	initlog.SetReportCaller(true)
	pid := int64(os.Getpid())
	rotateFileHook, err, logFileName := NewRotateFileHook(RotateFileConfig{
		Filename:   filepath.Join(logFilepath, "k2_go_agent_init_"+strconv.FormatInt(pid, 10)+"_"+uuid+".log"),
		MaxSize:    10, // megabytes
		MaxBackups: 500,
		MaxAge:     2, //days
		Level:      logrus.TraceLevel,
		Formatter:  &formatter,
	})

	LogfileAbsPath = logFileName
	if err != nil {
		log.Errorln("Error during creating log file ", err)
	}
	initlog.SetOutput(ioutil.Discard) // if output not discarded, it will send to stdout, this does not impact log file created through rotate file hook
	// Only log the warning severity or above.
	if os.Getenv("K2_DEBUG_MODE") == "true" {
		initlog.SetLevel(logrus.DebugLevel)
	} else {
		initlog.SetLevel(logrus.InfoLevel)
	}
	initlog.SetLevel(logrus.InfoLevel)
	initlog.AddHook(rotateFileHook)

}

func SetLogLevel(level string) {
	if os.Getenv("K2_DEBUG_MODE") == "true" {
		log.SetLevel(logrus.DebugLevel)
		return
	}
	switch strings.ToUpper(level) {
	case "TRACE":
		log.SetLevel(logrus.TraceLevel)
	case "DEBUG":
		log.SetLevel(logrus.DebugLevel)
	case "INFO":
		log.SetLevel(logrus.InfoLevel)
	case "WARN":
		log.SetLevel(logrus.WarnLevel)
	case "ERROR":
		log.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		log.SetLevel(logrus.FatalLevel)
	case "PANIC":
		log.SetLevel(logrus.PanicLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}
}

func GetLogger(loggerName string) *logrus.Entry {
	return log.WithFields(logrus.Fields{"logger": loggerName})
}

func InitLogger() *logrus.Logger {
	if initlog == nil {
		initlog = logrus.New()
	}
	return initlog
}

func NewStage(stageId, code, stage string) {
	if disable {
		return
	}
	logger1 := InitLogger()
	print := fmt.Sprintf("[STEP-%s][%s][BEGIN] %s", stageId, code, stage)
	logger1.Infoln(print)
}

func EndStage(stageId, code string) {
	if disable {
		return
	}
	logger1 := InitLogger()
	print := fmt.Sprintf("[STEP-%s][%s][COMPLETE]", stageId, code)
	logger1.Infoln(print)
	logger1.Infoln("\n")
}
func PrintInitlog(logs interface{}, stagecode string) {
	if disable {
		return
	}
	if initlog == nil {
		initlog = logrus.New()
	}
	print := fmt.Sprintf("[%s]: %s", stagecode, logs)
	initlog.Infoln(print)
}

func PrintInitErrolog(logs string, stagecode string) {
	if disable {
		return
	}
	if initlog == nil {
		initlog = logrus.New()
	}
	print := fmt.Sprintf("[%s]: %s", stagecode, logs)
	initlog.Errorln(print)
}
func PrintWarnlog(logs string, stagecode string) {
	if disable {
		return
	}
	if initlog == nil {
		initlog = logrus.New()
	}
	print := fmt.Sprintf("[%s]: %s", stagecode, logs)
	initlog.Warnln(print)
}

func Disableinitlogs() {
	disable = true
}
