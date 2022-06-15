// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_impl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	k2map "github.com/k2io/go-k2secure/v2/internal/k2secure_hashmap"
	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2model "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var debug = true
var id2sqlprepare = sync.Map{}
var logger = logging.GetLogger("impl")
var lock sync.Mutex
var firstEvent = true
var grpcMap = &k2map.HashMap{}
var fastHttpMap = &k2map.HashMap{}

type K2secureimpl struct {
}

// ---------------------------------------------------
// func: printInternal - uses golang's debug method
// ---------------------------------------------------
func printInternal(id string, s string) {
	if debug {
		logger.Debugln(id + " pid:" + strconv.Itoa(syscall.Getpid()) + " " + s)
	}
}

func printStackTrace() {
	pc := make([]uintptr, 10)
	n := runtime.Callers(4, pc)
	frames := runtime.CallersFrames(pc[:n])
	_, _, _, _, stkjson, _ := PresentStack(frames, "")
	logger.Info("Hooked Called before Initialize K2 Web server Hooks", stkjson)

	return
}

// ---------------------------------------------------
// func: k2Ready - ready to send events, hooked
// ---------------------------------------------------
func k2Ready(id string) bool {
	if k2i.Info == nil {
		printStackTrace()
		printInternal(id, "k2Ready exit - info not set")
		return false
	}
	if k2i.Info.SecureWS == nil {
		printStackTrace()
		printInternal(id, "k2Ready exit - WS not ready")
		return false
	}
	if k2i.Info.AgentInfo.Hooked == false {
		printStackTrace()
		printInternal(id, "k2Ready exit - not hooked")
		return false
	}
	return true
}

func (k K2secureimpl) K2UpdateHttpConnsOut(dest, dport, urlx string) {
	UpdateHttpConnsOut(dest, dport, urlx)
}

func (k K2secureimpl) K2getTraceHeader(eventid *k2model.EventJson) (string, string) {
	if eventid == nil {
		return "", ""
	}
	id := getID()
	req := k2map.GetFromMap(id)
	if req != nil {
		request := req.(*k2model.Info_req)
		value := request.K2TraceData
		value += " " + k2i.Info.ApplicationInfo.AppUUID + "/" + eventid.APIID + "/" + eventid.ID + ";"
		return "K2-TRACING-DATA", strings.TrimSpace(value)
	}
	return "", ""
}

// ---------------------------------------------------
// func: K2dbexec interception of db exec
// ---------------------------------------------------
func (k K2secureimpl) K2dbprepare(q, p string) {
	if !k2Ready("pre.db.sql.prepare") {
		return
	}
	printInternal("k2dbprepare", q)
	id2sqlprepare.Store(p, q)
}

// ---------------------------------------------------
// func: K2dbquery interception of db query
// ---------------------------------------------------
func (k K2secureimpl) K2dbexecprepare(eventId, q_address string, qargs ...interface{}) *k2model.EventJson {
	qurey, _ := id2sqlprepare.Load(q_address)
	id2sqlprepare.Delete(q_address)
	//id2sqlprepare[q_address]=nil
	var arg11 []interface{}
	parameters := map[int]interface{}{}
	for i := range qargs {
		str := fmt.Sprintf("%v", qargs[i])
		parameters[i] = string(str)
	}
	tmp_map := map[string]interface{}{
		"query":      qurey,
		"parameters": parameters,
	}
	arg11 = append(arg11, tmp_map)
	return k.SendEvent(eventId, "SQL_DB_COMMAND", arg11)

}

// ---------------------------------------------------
// func: K2preExit interception of process exit
// ---------------------------------------------------
func (k K2secureimpl) K2preExit(code int) {
	if !k2Ready("pre.Exit") {
		return
	}
	q := strconv.FormatInt(int64(code), 10)
	printInternal("k2preExit", q)
	var arg []string
	arg = append(arg, q)
	// No Event to validate for now: k.K2Event( "SYSTEM_EXIT",arg)

	for i := 0; i < 50; i++ {
		time.Sleep(6 * time.Second)
		if 0 == k2i.K2GetUnflushed() {
			logger.Infoln("Exiting after flushing events... minutes:", strconv.Itoa(i))
			break
		}
	}
}

func (k K2secureimpl) K2FuncId(x interface{}) k2i.Tuple {

	vpc := reflect.ValueOf(x)
	pc := uintptr(vpc.Pointer())
	f := runtime.FuncForPC(pc)
	if f != nil {
		fi, li := f.FileLine(pc)
		return k2i.Tuple{A: f.Name(), B: fi, C: strconv.Itoa(li)}
	}
	unkTuple := k2i.Tuple{A: "unknownMethod", B: "unknownFile", C: "unknownLine"}
	return unkTuple
}

// ---------------------------------------------------
func (k K2secureimpl) K2CallerId(depth int) k2i.Tuple {
	unkTuple := k2i.Tuple{A: "unknownMethod", B: "unknownFile", C: "unknownLine"}
	pc, fi, li, ok := runtime.Caller(depth)
	if !ok {
		return unkTuple
	}
	f := runtime.FuncForPC(pc)
	if f != nil {
		return k2i.Tuple{A: f.Name(), B: fi, C: strconv.Itoa(li)}
	} else {
		return k2i.Tuple{A: "unknownMethod", B: fi, C: strconv.Itoa(li)}
	}
}

func (k K2secureimpl) SendEvent(eventId, category string, args interface{}) *k2model.EventJson {
	if !k2Ready("SendEvent") {
		return nil
	}
	return k.K2Event(eventId, category, args)
}

// ---------------------------------------------------
// func: k2lineMapLookup
// ---------------------------------------------------
var k2lineMap map[uintptr]k2i.Tuple

func k2lineMapLookup(u uintptr) (bool, k2i.Tuple) {
	unkTuple := k2i.Tuple{A: "unknownMethod", B: "unknownFile", C: "unknownLine"}
	t, ok := k2lineMap[u]
	if !ok {
		return false, unkTuple
	}
	return true, t
}

// ---------------------------------------------------
// func: K2getMap current lineMapping
// ---------------------------------------------------
func (k K2secureimpl) K2getMap(p interface{}) k2i.Tuple {
	vpc := reflect.ValueOf(p)
	pc := uintptr(vpc.Pointer())
	_, t := k2lineMapLookup(pc)
	return t
}

// ---------------------------------------------------
// func: K2setAddrMap set lineMapping
// ---------------------------------------------------
func (k K2secureimpl) K2setAddrMap(from uintptr, to, toc interface{}) string {

	unkTuple := k2i.Tuple{A: "unknownMethod", B: "unknownFile", C: "unknownLine"}
	t1 := unkTuple
	var name string
	f := runtime.FuncForPC(from)
	if f != nil {
		fi, li := f.FileLine(from)
		t1 = k2i.Tuple{A: f.Name(), B: fi, C: strconv.Itoa(li)}
		name = f.Name()
	} else {
		name = "unknown"
	}
	vpc := reflect.ValueOf(to)
	pc := uintptr(vpc.Pointer())
	k2lineMap[pc] = t1

	vpc = reflect.ValueOf(toc)
	pc = uintptr(vpc.Pointer())
	k2lineMap[pc] = t1

	return name
}

// ---------------------------------------------------
// func: K2eetMap set lineMapping
// ---------------------------------------------------
func (k K2secureimpl) K2setMap(from, to, toc interface{}) string {
	t1 := k.K2FuncId(from)

	vpc := reflect.ValueOf(to)
	pc := uintptr(vpc.Pointer())
	k2lineMap[pc] = t1

	vpc = reflect.ValueOf(toc)
	pc = uintptr(vpc.Pointer())
	k2lineMap[pc] = t1

	return t1.A
}

// ---------------------------------------------------
// func: K2associate current request
// ---------------------------------------------------

func (k K2secureimpl) K2associate(r *k2model.Info_req) {
	if !k2Ready("K2associate") {
		return
	}
	k2i.Info.EventData.RequestCount++
	if r.IsGrpc {
		cr := getID()
		data, err := grpcMap.Get(cr)
		if err {
			reqData := data.(*k2model.Info_grpc)
			r.ClientIp = reqData.ClientIp
			r.ClientPort = reqData.ClientPort
		}

	}
	UpdateHttpConnsIn(r)
	associate(r)
	return
}

// ---------------------------------------------------
// func: K2dissociate current request
// ---------------------------------------------------
func (k K2secureimpl) K2dissociate() {
	if !k2Ready("K2dissociate") {
		return
	}
	disassociate(getID())
	return
}

// ---------------------------------------------------
// func: K2getRequest current request
// ---------------------------------------------------
func (k K2secureimpl) K2getRequest() *k2model.Info_req {
	if !k2Ready("K2getRequest") {
		return nil
	}
	id := getID()
	req := k2map.GetFromMap(id)
	if req != nil {
		return req.(*k2model.Info_req)
	}
	return nil
}

func (k K2secureimpl) K2calculateApiId() {
	if !k2Ready("K2calculateApiId") {
		return
	}
	id := getID()
	req := k2map.GetFromMap(id)
	if req != nil {
		request := getRequest()
		if request.ApiId == "" {
			pc := make([]uintptr, 10)
			n := runtime.Callers(4, pc)
			frames := runtime.CallersFrames(pc[:n])
			_, _, _, _, stkjson, apiId := PresentStack(frames, request.Method)
			request.ApiId = apiId
			request.Stacktrace = stkjson
		}
	}
	return
}

func (k K2secureimpl) K2associateQueryParam(body interface{}, data []byte) {
	if !k2Ready("K2grpc.K2associateQueryParam") {
		return
	}
	request := getRequest()
	if request == nil {
		logger.Errorln("(K2associateQueryParam) GRPC Request Not Found")
		return
	}
	requestbytes := request.GrpcByte
	if k2utils.CheckGrpcByte(requestbytes, data) {

		logger.Debugln("K2associateQueryParam : IsByte Data equals True ,GRPC Request Data ")
		request.GrpcBody = append(request.GrpcBody, body)

	} else {
		logger.Debugln("K2associateQueryParam : IsByte Data equals False ,GRPC Responce Data ")
		logger.Debugln(requestbytes)
		logger.Debugln(data)
	}
}

func (k K2secureimpl) K2associateGrpcByte(data []byte) {
	if !k2Ready("K2grpc.K2associateGrpcByte") {
		return
	}
	request := getRequest()
	if request == nil {
		logger.Errorln("(K2associateGrpcByte) GRPC Request Not Found")
		return
	}
	request.GrpcByte = append(request.GrpcByte, data)
}

func (k K2secureimpl) K2associateBlockingResponse(id, apiId string, counter bool) {
	if !k2Ready("K2.K2associateBlockingResponse") {
		return
	}
	dummy := strings.Split(id, ":")
	if len(dummy) >= 2 {
		id = dummy[0]
	}
	request := getRequestWithId(id)
	if request == nil {
		logger.Errorln("(K2associateBlockingResponse) Request Not Found with ID", id, "  getID()  ", getID())
		return
	}
	if !request.BlockedResponse {
		request.BlockedResponse = counter
		request.BlockedApis = apiId
	}
}

func (k K2secureimpl) K2IsHttpBlocked() (bool, string) {
	if !k2Ready("K2.K2IsHttpBlocked") {
		return false, ""
	}
	id := getID()
	request := getRequestWithId(id)
	if request == nil {
		logger.Errorln("(K2IsHttpBlocked) Request Not Found ID ", id, "  getID()  ", getID())
		return false, ""
	}
	return request.BlockedResponse, request.BlockedApis
}

func (k K2secureimpl) K2IsApiBlocked(id string) bool {
	time.Sleep(1 * time.Second)
	if !k2Ready("K2.K2IsApiBlocked") {
		return false
	}
	dummy := strings.Split(id, ":")
	if len(dummy) >= 2 {
		id = dummy[0]
	}
	request := getRequestWithId(id)
	if request == nil {
		logger.Errorln("(K2IsApiBlocked) Request Not Found ID ", id, "  getID()  ", getID())
		return false
	}
	return request.BlockedResponse
}

func (k K2secureimpl) IsRequest() bool {
	request := getRequest()
	if request == nil {
		return false
	}
	return true

}
func (k K2secureimpl) GetFuzzHeader() string {
	request := getRequest()
	if request == nil {
		return ""
	} else {
		return request.K2RequestIdentifier
	}
}

// ---------------------------------------------------
// func: K2getID current request ID
// ---------------------------------------------------
func (k K2secureimpl) K2getID() string {
	id := getID()
	return id
}

//Note: cannot place any Logging in this method - called from newproc

func (k K2secureimpl) K2associateGoRoutine(caller, callee int64) {
	cr := strconv.FormatInt(caller, 10)
	ce := strconv.FormatInt(callee, 10)
	associateGoroutine(cr, ce)
}

func (k K2secureimpl) K2removeGoRoutine(caller int64) {
	cr := strconv.FormatInt(caller, 10)
	disassociate(cr)
}

func (k K2secureimpl) K2associateGrpcData(data *k2model.Info_grpc) {
	if data != nil {
		cr := getID()
		grpcMap.Set(cr, data)
	}
}
func (k K2secureimpl) K2delGrpcData() {
	cr := getID()
	grpcMap.Del(cr)
}

// Functions to store fasthttp connection data for sbi

func (k K2secureimpl) K2associateFastHttpData(data net.Conn) {
	if data != nil {
		cr := getID()
		fastHttpMap.Set(cr, data)
	}
}

func (k K2secureimpl) K2GetFastHttpData() (data net.Conn) {
	cr := getID()
	data1, err := fastHttpMap.Get(cr)
	if !err {
		return nil
	}
	return data1.(net.Conn)
}

func (k K2secureimpl) K2RemoveFastHttpData() {
	cr := getID()
	fastHttpMap.Del(cr)
}

func StringSHA256(f string) string {
	sum := sha256.Sum256([]byte(f))
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

// ---------------------------------------------------
// Func: isUser method
// ---------------------------------------------------
func isUser(aMethod, aFile, prevMethod, prevFile string) bool {

	// either reach main package OR different prefix.
	i := strings.LastIndex(aMethod, "/")
	aprefix := aMethod
	if i >= 0 {
		aprefix = aMethod[:i]
	}
	j := strings.LastIndex(prevMethod, "/")
	pprefix := prevMethod
	if j >= 0 {
		pprefix = prevMethod[:j]
	}
	//k2i.K2log(" isUser check ",aMethod,aFile,prevMethod,prevFile,aprefix,pprefix)
	if aprefix != pprefix {
		// k2i.K2log(" isUser check -- prefix mismatch",aMethod,aFile,prevMethod,prevFile,aprefix,pprefix)
		return true
	}
	if strings.HasPrefix(aMethod, "main.") {
		// k2i.K2log(" isUser check -- main.*",aMethod,aFile,prevMethod,prevFile,aprefix,pprefix)
		return true
	}
	return false
}

// ---------------------------------------------------
// func: PresentStack - format stack for JSON
// note: new format has funcname(filename:line)
// ---------------------------------------------------
func PresentStack(frames *runtime.Frames, method string) (string, string, string, string, []string, string) {
	userfile := "NoFILE"
	usermethod := "NoMethod"
	userline := "0"
	srcmethod := "noMethod"
	id := k2i.Identity()
	j := ""
	//comma:=""
	count := 0
	apiId := ""
	apiIdsep := ""
	pf := ""
	pm := ""

	var arg []string

	isUserSet := false
	for true {
		frame, more := frames.Next()
		m := frame.Function
		f := frame.File
		line := strconv.Itoa(frame.Line)
		// k2i.K2log("PresentStack: frame... ",f,m,line)
		if count == 0 {
			u := frame.Entry
			check, k := k2lineMapLookup(u)
			if check {
				m = k.A
				f = k.B
				line = k.C
				srcmethod = m
			}
		} else if (count >= 1) && !isUserSet && isUser(f, m, pf, pm) {
			userfile = f //user func is caller of our hook API
			usermethod = m
			userline = line
			isUserSet = true
		}

		if !strings.HasPrefix(m, id) {
			apiId = apiId + apiIdsep + m
			apiIdsep = "||"
			j = m + "(" + f + ":" + line + ")"
			arg = append(arg, j)

			// comma=","
		}
		count++
		pf = f //previous
		pm = m
		if !more {
			if (len(userfile) == len(usermethod)) && (len(usermethod) == 0) {
				userfile = f
				usermethod = m
				userline = line
			}
			break
		}
	}
	j = "[" + j + "]"
	apiId = StringSHA256(apiId + "||" + method)
	return srcmethod, userfile, usermethod, userline, arg, apiId
}

// ---------------------------------------------------
// func: K2Event - create and send event
// ---------------------------------------------------
func (k K2secureimpl) K2Event(eventId, category string, args interface{}) *k2model.EventJson {
	var tmp_event k2model.EventJson

	// fmt.Println("event_arg11")
	// fmt.Println(args)
	req := getRequest()
	if !k2Ready("K2Event:"+category) || (req == nil) {

		printInternal(category, "no incoming skipping Event")
		return nil
	}
	ecategory := category
	if category == "SQL_DB_COMMAND" {
		//TODO: recognize underlying db type -- MYSQL, MSSQL, SQLITE, etc.
		ecategory = "SQLITE"
	} else if category == "NOSQL_DB_COMMAND" {
		//MYSQL, MSSQL, SQLITE, etc.
		ecategory = "MONGO"
	}

	pc := make([]uintptr, 10)
	n := runtime.Callers(4, pc)
	frames := runtime.CallersFrames(pc[:n])
	tmp_event.GroupName = k2i.Info.EnvironmentInfo.GroupName
	tmp_event.NodeID = k2i.Info.EnvironmentInfo.NodeId
	tmp_event.CustomerID = k2i.Info.CustomerInfo.CustomerId
	tmp_event.EmailID = k2i.Info.CustomerInfo.EmailId
	srcMethod, userFile, userMethod, lineno, stkjson, apiId := PresentStack(frames, (*req).Method)

	if len(stkjson) > 120 {
		stkjson = stkjson[:120]
	}
	if category == "REFLECTED_XSS" && (*req).ApiId != "" {
		apiId = (*req).ApiId
		stkjson = (*req).Stacktrace
	}

	tmp_event.JSONName = "Event"
	tmp_event.CollectorVersion = k2utils.CollectorVersion
	tmp_event.JSONVersion = k2utils.JsonVersion
	tmp_event.CollectorType = k2utils.CollectorType
	tmp_event.Language = "GOLANG"
	tmp_event.Framework = "net/http"
	tmp_event.Pid = k2i.Info.ApplicationInfo.Pid
	tmp_event.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	tmp_event.StartTime = k2i.Info.ApplicationInfo.Starttimestr
	tmp_event.SourceMethod = srcMethod
	tmp_event.UserMethodName = userMethod
	tmp_event.LineNumber = lineno
	tmp_event.UserFileName = userFile
	tmp_event.EventGenerationTime = strconv.FormatInt(time.Now().Unix()*1000, 10)
	tmp_event.ID = getEventID(eventId)
	tmp_event.CaseType = category
	tmp_event.APIID = apiId
	tmp_event.EventCategory = ecategory
	tmp_event.Parameters = args
	tmp_event.BlockingProcessingTime = "1"
	tmp_event.HTTPRequest.ParameterMap = (*req).Queryparam
	clientPort := (*req).ClientPort
	if clientPort == "" {
		clientPort = "-1"
	}
	serverPort := (*req).ServerPort
	if serverPort == "" {
		serverPort = "-1"
	}
	tmp_event.HTTPRequest.Body = (*req).Body
	tmp_event.HTTPRequest.RawRequest = (*req).RawRequest
	tmp_event.HTTPRequest.Method = (*req).Method
	tmp_event.HTTPRequest.URL = (*req).Url
	tmp_event.HTTPRequest.ClientIP = (*req).ClientIp
	tmp_event.HTTPRequest.ClientPort = clientPort
	tmp_event.HTTPRequest.Headers = (*req).HeaderMap
	tmp_event.HTTPRequest.ContentType = (*req).ContentType
	tmp_event.BuildNumber = k2utils.BuildNumber
	tmp_event.HTTPRequest.ContextPath = k2i.Info.ApplicationInfo.ContextPath
	tmp_event.PolicyVersion = k2i.Info.GlobalData.Version
	tmp_event.HTTPRequest.ServerPort = serverPort
	tmp_event.HTTPRequest.ServerName = (*req).ServerName
	tmp_event.IsIASTEnable = false
	k2FuzzHeader := (*req).K2RequestIdentifier
	tmp_event.Stacktrace = make([]string, 0)
	tmp_event.CompleteStacktrace = make([]string, 0)
	if k2FuzzHeader == "" {
		tmp_event.Stacktrace = stkjson
	}

	tmp_event.IsAPIBlocked = checkApiBlockingNeeded(apiId)
	if k2i.Info.GlobalData.VulnerabilityScan.Enabled && k2i.Info.GlobalData.VulnerabilityScan.IastScan.Enabled {
		if k2FuzzHeader != "" && k2utils.CaseInsensitiveContains(k2FuzzHeader, apiId) && k2utils.CaseInsensitiveContains(k2FuzzHeader, ":K2:VULNERABLE:K2:") {
			tmp_event.CompleteStacktrace = stkjson
		}
		tmp_event.IsIASTEnable = true
	}
	protocol := (*req).Protocol
	tmp_event.HTTPRequest.Protocol = protocol
	if (*req).IsGrpc {
		tmp_event.HTTPRequest.IsGRPC = true
		tmp_event.Framework = "gRPC"
		K2Body := (*req).GrpcBody
		grpc_bodyJson, err1 := json.Marshal(K2Body)
		if err1 != nil {
			logger.Errorln("K2Event: grpc_body JSON invalid" + string(grpc_bodyJson))
			return nil
		} else {
			tmp_event.HTTPRequest.Body = string(grpc_bodyJson)
		}
	}
	event_json, err1 := json.Marshal(tmp_event)
	if err1 != nil {
		logger.Errorln("K2Event: JSON invalid" + string(event_json))
		return nil
	}
	if firstEvent {
		logging.NewStage("7", "EVENT", "First Event processed & sent")
		logging.PrintInitlog("First event intercepted : "+category, "EVENT")
		logging.PrintInitlog("First event processed : "+string(event_json), "EVENT")
		logging.EndStage("7", "EVENT")
		firstEvent = false
		logging.Disableinitlogs()
	}
	if k2i.Info.AgentInfo.SecureWSready {
		logger.Debugln("k2Event", "ready to send to IC: "+string(event_json))
		k2i.Info.SecureWS.Send([]byte(string(event_json)))
	} else {
		logger.Errorln("k2Event", "NOT ready NOT sending to IC:"+string(event_json))
	}
	return &tmp_event
}

func (k K2secureimpl) SendExitEvent(event *k2model.EventJson) {
	req := getRequest()
	if req == nil || (*req).K2RequestIdentifier == "" {
		return
	}
	if !(k2i.Info.GlobalData.VulnerabilityScan.Enabled && k2i.Info.GlobalData.VulnerabilityScan.IastScan.Enabled) {
		return
	}
	k2FuzzHeader := (*req).K2RequestIdentifier

	if !(k2FuzzHeader != "" && k2utils.CaseInsensitiveContains(k2FuzzHeader, event.APIID) && k2utils.CaseInsensitiveContains(k2FuzzHeader, ":K2:VULNERABLE:K2:")) {
		return
	}
	var tmp_event k2model.Exitevent
	tmp_event.GroupName = k2i.Info.EnvironmentInfo.GroupName
	tmp_event.NodeID = k2i.Info.EnvironmentInfo.NodeId
	tmp_event.CustomerID = k2i.Info.CustomerInfo.CustomerId
	tmp_event.EmailID = k2i.Info.CustomerInfo.EmailId
	tmp_event.JSONName = "exit-event"
	tmp_event.BuildNumber = k2utils.BuildNumber
	tmp_event.JSONVersion = k2utils.JsonVersion
	tmp_event.PolicyVersion = k2i.Info.GlobalData.Version
	tmp_event.ApplicationUUID = k2i.Info.ApplicationInfo.AppUUID
	tmp_event.K2RequestIdentifier = (*req).K2RequestIdentifier
	tmp_event.CaseType = event.CaseType
	tmp_event.ExecutionId = getEventID(event.ID)
	event_json, err1 := json.Marshal(tmp_event)
	if err1 != nil {
		logger.Errorln("K2Event: JSON invalid" + string(event_json))
		return
	}
	if k2i.Info.AgentInfo.SecureWSready {
		logger.Debugln("k2Event", "ready to send to IC Exit Event: "+string(event_json))
		k2i.Info.SecureWS.Send([]byte(string(event_json)))
	} else {
		logger.Errorln("k2Event", "NOT ready NOT sending to IC:"+string(event_json))
	}
}

// ---------------------------------------------------
// -- getRequest
// ---------------------------------------------------
func getRequest() *k2model.Info_req {
	id := getID()
	req := k2map.GetFromMap(id)
	// inUseLen, pLen, sLen := k2map.Len()
	// logger.Debugln("Len: ", inUseLen, pLen, sLen, "NumofR :", runtime.NumGoroutine())
	if req != nil {
		return req.(*k2model.Info_req)
	}
	return nil
}
func getRequestWithId(id string) *k2model.Info_req {
	req := k2map.GetFromMap(id)
	if req != nil {
		return req.(*k2model.Info_req)
	}
	return nil
}

// ---------------------------------------------------
// -- associate request with goroutines ID
// ---------------------------------------------------
func associate(a *k2model.Info_req) string {
	id := getID()
	k2map.InsertIntoMap(id, a)
	return id
}

// ---------------------------------------------------
// -- get Http request with goroutines ID
// --------------------------------------------------
func getGoroutinesRequest(id string) *k2model.Info_req {
	req := k2map.GetFromMap(id)
	if req == nil {
		return nil
	}
	return req.(*k2model.Info_req)
}

// -------------------------------------------------
// associate Http request from caller goroutines to
// calleeg oroutines
// -------------------------------------------------
func associateGoroutine(caller, callee string) {
	req := k2map.GetFromMap(caller)
	if req != nil {
		k2map.InsertIntoMap(callee, req)
	}
}

// ---------------------------------------------------
// -- disassociate request with ID
// -- For disassociate inserting nill into with same key
// ---------------------------------------------------
func disassociate(id string) {

	k2map.InsertIntoMap(id, nil)
}

// ---------------------------------------------------
// -- get current goroutine ID
// ---------------------------------------------------
func getID() string {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	id := string(b)
	//k2i.K2log(" -- current ID is ... ",id)
	return id
}

// ---------------------------------------------------
// -- goroutineID from bytearray
// -- sometimes we have already extracted stack. parse it.
// ---------------------------------------------------
// func getIDfrombytes(b []byte) string {
// 	b = bytes.TrimPrefix(b, []byte("goroutine "))
// 	b = b[:bytes.IndexByte(b, ' ')]
// 	return string(b)
// }

func init() {
	k2lineMap = make(map[uintptr]k2i.Tuple, 0)
}

func getEventID(id string) string {
	id = getID() + ":" + id
	return id
}

func checkApiBlockingNeeded(apiId string) bool {
	if !(k2i.Info.GlobalData.ProtectionMode.Enabled && k2i.Info.GlobalData.ProtectionMode.APIBlocking.Enabled) {
		return false
	}

	if k2utils.Contains(k2i.Info.GlobalPolicy.AllowedApis, apiId) {
		return false
	}

	if k2utils.Contains(k2i.Info.GlobalPolicy.BlockedApis, apiId) {
		return true
	}
	return k2i.Info.GlobalData.ProtectionMode.APIBlocking.ProtectAllApis
}
