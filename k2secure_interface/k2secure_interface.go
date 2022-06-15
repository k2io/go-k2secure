// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_interface

import (
	"errors"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/go-co-op/gocron"
	k2model "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
)

type Info_struct struct {
	Secure          Secureiface
	EventData       k2model.EventData
	AgentInfo       k2model.GoAgentInfo
	EnvironmentInfo k2model.EnvironmentInfo
	CustomerInfo    k2model.CustomerInfo
	ApplicationInfo k2model.RunningApplicationInfo
	HookCalledCount uint64
	Log             *log.Logger
	GlobalData      k2model.WebAppPolicy
	GlobalPolicy    k2model.GlobalPolicy
	SecureWS        SecureWSiface
	IsK2Disable     bool
}

var scheduler *gocron.Scheduler

// ---------------------------------------------------
// struct: Tuple of 3 entries for stack entry
// ---------------------------------------------------
type Tuple struct {
	A, B, C string
}

// ---------------------------------------------------
// interface: Secureiface interface
// ---------------------------------------------------
type Secureiface interface {
	K2UpdateHttpConnsOut(string, string, string)
	K2preExit(int)
	K2dbprepare(string, string)
	K2dbexecprepare(string, string, ...interface{}) *k2model.EventJson
	K2getRequest() *k2model.Info_req
	K2getID() string
	K2associate(*k2model.Info_req)
	K2dissociate()
	K2CallerId(int) Tuple
	K2FuncId(interface{}) Tuple
	K2setMap(interface{}, interface{}, interface{}) string
	K2setAddrMap(uintptr, interface{}, interface{}) string
	HookWrap(interface{}, interface{}, interface{}) error
	HookWrapInterface(interface{}, interface{}, interface{}) error
	HookWrapRaw(uintptr, interface{}, interface{}) error
	HookWrapRawNamed(string, interface{}, interface{}) (string, error)
	K2getMap(interface{}) Tuple
	K2associateGoRoutine(caller, callee int64)
	K2removeGoRoutine(caller int64)
	K2associateQueryParam(interface{}, []byte)
	K2associateGrpcByte([]byte)
	InitSyms()
	K2calculateApiId()
	IsRequest() bool
	K2associateGrpcData(*k2model.Info_grpc)
	K2delGrpcData()
	K2getTraceHeader(*k2model.EventJson) (string, string)
	SendExitEvent(*k2model.EventJson)
	K2associateFastHttpData(net.Conn)
	K2RemoveFastHttpData()
	K2GetFastHttpData() net.Conn
	SendEvent(eventId, category string, args interface{}) *k2model.EventJson
	GetFuzzHeader() string
	K2associateBlockingResponse(string, string, bool)
	K2IsApiBlocked(string) bool
	K2IsHttpBlocked() (bool, string)
}

// ---------------------------------------------------
// interface: websocket interface
// ---------------------------------------------------
type SecureWSiface interface {
	Send([]byte) int
	UploadLogOnRotationWS()
}

var (
	LOG_FILE_PATH           string
	CVE_STARPUP_COMMAD      string
	CVE_STARPUP             string
	DEPENDENCY_CHECK_COMMAD string
	CVE_TAR_SPACE           string
	APPLICATION_POLICY      string
	CONFIG_PATH             string
)

const k2root = "k2root"

func InitConst(k2Home, env, uuid string) {
	if k2Home == "" {
		if k2utils.CaseInsensitiveEquals("windows", env) {
			k2Home = "C:\\Users\\Public\\K2\\k2root"
		} else {
			k2Home = "/opt/k2root"
		}
	}
	LOG_FILE_PATH = filepath.Join(k2Home, k2root, "logs", "language-agent", uuid)
	CVE_TAR_SPACE = filepath.Join(k2Home, k2root, "tmp", "language-agent", uuid)
	APPLICATION_POLICY = filepath.Join(k2Home, k2root, "config", "language-agent", uuid)
	CONFIG_PATH = filepath.Join(k2Home, k2root, "config")

	if k2utils.CaseInsensitiveEquals("windows", env) {
		CVE_STARPUP = "powershell.exe"
		CVE_STARPUP_COMMAD = filepath.Join(CVE_TAR_SPACE, "K2", "startup.ps1")
		DEPENDENCY_CHECK_COMMAD = "powershell.exe " + filepath.Join(CVE_TAR_SPACE, "K2", "dependency-check.ps1")

	} else {
		if k2utils.CaseInsensitiveEquals("darwin", env) {
			CVE_STARPUP = "bash"
			CVE_STARPUP_COMMAD = filepath.Join(CVE_TAR_SPACE, "K2", "startup.sh")
			DEPENDENCY_CHECK_COMMAD = "bash " + filepath.Join(CVE_TAR_SPACE, "K2", "dependency-check.sh")
		} else {
			CVE_STARPUP = "sh"
			CVE_STARPUP_COMMAD = filepath.Join(CVE_TAR_SPACE, "K2", "startup.sh")
			DEPENDENCY_CHECK_COMMAD = "sh " + filepath.Join(CVE_TAR_SPACE, "K2", "dependency-check.sh")

		}
	}

}

// // ---------------------------------------------------
// // func: K2log - accessible as k2secure_interface.K2log
// // ---------------------------------------------------
// func K2log(v ...interface{}) {
// 	if Info != nil && Info.Secure != nil {
// 		Info.Secure.K2log(v...)
// 	} else {
// 		println(v)
// 	}
// }
func Identity() string {
	return "github.com/k2io/go-k2secure/v2"
}

// // ------------------------------------------------------
// // func: K2logf - accessible as k2secure_interface.K2logf
// // ------------------------------------------------------
// func K2logf(f string, v ...interface{}) {
// 	if Info != nil && Info.Secure != nil {
// 		Info.Secure.K2logf(f, v...)
// 	} else {
// 		println(f, v)
// 	}
// }

// ---------------------------------------------------------
// func: K2CallerId - accessible as k2secure_interface.K2CallerId
// ---------------------------------------------------------
func K2CallerId(depth int) Tuple {
	unkTuple := Tuple{"unknownMethod", "unknownFile", "unknownLine"}
	if Info.Secure != nil {
		return Info.Secure.K2CallerId(depth + 1)
	} else {
		return unkTuple
	}
}

// ---------------------------------------------------------
// func: K2FuncId - accessible as k2secure_interface.K2CallerId
// ---------------------------------------------------------
func K2FuncId(pc interface{}) Tuple {
	unkTuple := Tuple{"unknownMethod", "unknownFile", "unknownLine"}
	if Info.Secure != nil {
		return Info.Secure.K2FuncId(pc)
	} else {
		return unkTuple
	}
}

// ---------------------------------------------------------
// func: K2getID - accessible as k2secure_interface.K2getID
// ---------------------------------------------------------
func K2getID() string {
	if Info.Secure != nil {
		return Info.Secure.K2getID()
	} else {
		return ""
	}
}

// ---------------------------------------------------
// Data: Global data initializations
// ---------------------------------------------------
var Info *Info_struct

func InitK2BaseInfo(scheduler bool) {
	Info = new(Info_struct)
	Info.EventData = k2model.EventData{}
	Info.AgentInfo = k2model.GoAgentInfo{}
	Info.EnvironmentInfo = k2model.EnvironmentInfo{}
	Info.CustomerInfo = k2model.CustomerInfo{}
	Info.ApplicationInfo = k2model.RunningApplicationInfo{}
	Info.GlobalData = k2model.WebAppPolicy{}
	Info.GlobalPolicy = k2model.GlobalPolicy{}
	Info.IsK2Disable = false
	Info.HookCalledCount = 0
	if scheduler {
		initialiseTaskScheduler()
	}
}

func initialiseTaskScheduler() {
	scheduler = gocron.NewScheduler(time.Local)
	scheduler.StartAsync()
	scheduler.TagsUnique()
}

func TaskScheduler() *gocron.Scheduler {
	return scheduler
}

//var k2map  = make(map[uintptr]Tuple) //hook map
// ---------------------------------------------------
// func: K2setMap - insert mapping hook fn to origFn
// ---------------------------------------------------
func K2setMap(from, to, toc interface{}) string {
	if Info.Secure != nil {
		return Info.Secure.K2setMap(from, to, toc)
	} else {
		return "unknown"
	}
}

// ---------------------------------------------------
// func: K2setAddrMap - insert mapping hook fn to origFn
// ---------------------------------------------------
func K2setAddrMap(from uintptr, to, toc interface{}) string {
	if Info.Secure != nil {
		return Info.Secure.K2setAddrMap(from, to, toc)
	} else {
		return "unknown"
	}
}

// ---------------------------------------------------
// func: K2getMap - retrieve mapping hook fn to origFn
// ---------------------------------------------------
func K2getMap(from interface{}) Tuple {
	unkTuple := Tuple{"unknownMethod", "unknownFile", "unknownLine"}
	if Info.Secure != nil {
		return Info.Secure.K2getMap(from)
	} else {
		return unkTuple
	}
}

func HookWrap(f, t, tc interface{}) error {
	if Info.Secure != nil {
		return Info.Secure.HookWrap(f, t, tc)
	} else {
		return errors.New("K2-not-initialized")
	}
}
func HookWrapInterface(f, t, tc interface{}) error {
	if Info.Secure != nil {
		return Info.Secure.HookWrapInterface(f, t, tc)
	} else {
		return errors.New("K2-not-initialized")
	}
}
func HookWrapRaw(f uintptr, t, tc interface{}) error {
	if Info.Secure != nil {
		return Info.Secure.HookWrapRaw(f, t, tc)
	} else {
		return errors.New("K2-not-initialized")
	}
}
func HookWrapRawNamed(f string, t, tc interface{}) (string, error) {
	if Info.Secure != nil {
		return Info.Secure.HookWrapRawNamed(f, t, tc)
	} else {
		return "", errors.New("K2-not-initialized")
	}
}

var unflushed = 0

func K2GetUnflushed() int {
	return unflushed
}
func K2SetUnflushed(c int) {
	unflushed = c
}
func K2ResetUnflushed() {
	unflushed = 0
}

var earlyListen []string

func EarlyListen(i string) {
	earlyListen = append(earlyListen, i)
}

func ClearEarlyListen() []string {
	s := earlyListen
	earlyListen = make([]string, 0)
	return s
}
func init() {
	earlyListen = make([]string, 0)
}

var drop_hooks_requested = false

func DropHooksRequest() bool {
	return drop_hooks_requested
}
func SetDropHooksRequest() {
	drop_hooks_requested = true
}
