// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_intercept

import (
	"bytes"
	"debug/elf"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2Utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
	k2ws "github.com/k2io/go-k2secure/v2/k2secure_ws"
	"github.com/sirupsen/logrus"
)

var logger = logging.GetLogger("intercept")

const K2_SEP = ":K2:"

func K2Exception() error {
	return fmt.Errorf(`raise K2CyberSecurityException.new "K2 has detected an attack.}`)

}
func Identity() string {
	return k2i.Identity()
}

func DropHooksRequest() bool {
	return k2i.DropHooksRequest()
}
func SetDropHooksRequest() {
	k2i.SetDropHooksRequest()
}

func K2associateGoRoutine(caller, callee int64) {
	if k2i.Info.Secure == nil {
		return
	}
	k2i.Info.Secure.K2associateGoRoutine(caller, callee)
}

func K2removeGoRoutine(caller int64) {
	if k2i.Info.Secure == nil {
		return
	}
	k2i.Info.Secure.K2removeGoRoutine(caller)
}

// ---------------------------------------------------
// Func: earlyHookExit - debug function for id early exits
// ---------------------------------------------------
func earlyHookExit(a string) {
	logger.Debugln("Early exit from hook - " + a)
}

// --------------------------------------------------------------------------
// Func HookWrap - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func HookWrap(from, to, toc interface{}) error {
	return k2i.HookWrap(from, to, toc)
}

// --------------------------------------------------------------------------
// Func HookWrapInterface - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func HookWrapInterface(from, to, toc interface{}) error {
	return k2i.HookWrapInterface(from, to, toc)
}

// --------------------------------------------------------------------------
// Func HookWrapRaw - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func HookWrapRaw(from uintptr, to, toc interface{}) error {
	return k2i.HookWrapRaw(from, to, toc)
}

// --------------------------------------------------------------------------
// Func HookWrapRawDebugInterface - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func HookWrapRawNamed(from string, to, toc interface{}) (string, error) {
	return k2i.HookWrapRawNamed(from, to, toc)
}

// ---------------------------------------------------
// Func: K2EndHook -- for complex hook this represents
//       call that can be overlaid.
// ---------------------------------------------------
//go:noinline
func K2EndHook() {
	if k2i.Info == nil {
		return
	}
	K2EndHookx()
	K2EndHookx()
	K2EndHookx()
	return
}

//go:noinline
func K2EndHookx() {
	if k2i.Info == nil {
		return
	}
	return
}

// ---------------------------------------------------
// Func: K2OKhook -- initialized -- ok to hook
// ---------------------------------------------------
func K2OKhook() bool {
	if k2i.Info == nil {
		logger.Debugln("k2secure_intercept.K2OK - false - noInfo")
		return false
	}
	return true
}

// ---------------------------------------------------
// Func: K2OK -- initialized
// ---------------------------------------------------
func K2OK(a string) bool {
	if k2i.Info == nil {
		logger.Debugln("k2secure_intercept.K2OK - false - Info nil", a)
		return false
	}
	if k2i.Info.Secure == nil {
		logger.Debugln("k2secure_intercept.K2OK - false - noWS", a)
		return false
	}
	if k2i.Info.AgentInfo.Hooked != true {
		logger.Debugln("k2secure_intercept.K2OK - false - notHooked", a)
		return false
	}
	logger.Debugln("k2secure_intercept.K2OK - true: ", a, " ", currentURL())
	//TODO: pid-check if appserver forks reinit.
	return true //testing
}

func IsHooked() bool {
	if k2i.Info == nil {
		return false
	}
	return k2i.Info.AgentInfo.Hooked
}
func SetHooked() {
	if k2i.Info == nil {
		return
	}
	k2i.Info.AgentInfo.Hooked = true
}

// ---------------------------------------------------
// Func: K2request - interception of request creation
// hook where outgoing http request object is created
// ---------------------------------------------------
func K2request(url, host, port string, isGrpc bool, header map[string][]string) *models.EventJson {
	if !K2OK("pre.OutboundRequest") {
		logger.Infoln("---- OUTGONG K2request called(NOT SET nil Ibfo)" + host + " " + url + " " + port)
		return nil
	}
	logger.Infoln("---- OUTGOING K2request called host:" + host + " url:" + url + " header:" + port)

	if !isGrpc {
		ip, dport := getIpAndPort(host)
		if ip != "" {
			host = ip
		}
		if dport != "" {
			port = dport
		}
	}
	calledID := increaseCount()

	var args []interface{}
	args = append(args, url)
	k2event := k2i.Info.Secure.SendEvent(calledID, "HTTP_REQUEST", args)

	if header != nil {
		for key, _ := range header {
			if k2Utils.CaseInsensitiveEquals("K2_API_ACCESSOR_TOKEN", key) {
				return k2event
			}
		}
	}
	k2i.Info.Secure.K2UpdateHttpConnsOut(host, port, url)
	return k2event
}

// ---------------------------------------------------
// Func: K2preServeHTTP - interception of incoming request
// ---------------------------------------------------
func K2preServeHTTP(url, host string, hdrMap map[string][]string, method string, body []byte, queryparam map[string][]string, protocol, serverName string) {
	t := time.Now()
	if !K2OK("pre.ServeHTTP") {
		earlyHookExit("pre.serveHTTP")
		return
	}

	clientIp := ""
	clientPort := ""
	if host != "" {
		clientIp, clientPort = getIpAndPort(host)
	}
	filterHeader := map[string]string{}
	k2RequestIdentifier := ""
	traceData := ""
	api_caller := ""
	for k, v := range hdrMap {
		if k2Utils.CaseInsensitiveEquals(k, "K2-TRACING-DATA") {
			traceData = strings.Join(v, ",")
		} else if k2Utils.CaseInsensitiveEquals(k, "k2-fuzz-request-id") {
			k2RequestIdentifier = strings.Join(v, ",")
		} else if k2Utils.CaseInsensitiveEquals(k, "K2-API-CALLER") {
			api_caller = strings.Join(v, ",")
		} else {
			filterHeader[k] = strings.Join(v, ",")
		}
	}
	if traceData != "" {
		filterHeader["K2-TRACING-DATA"] = traceData
	}
	if k2RequestIdentifier != "" {
		filterHeader["K2-FUZZ-REQUEST-ID"] = k2RequestIdentifier
	}
	if api_caller != "" {
		filterHeader["K2-API-CALLER"] = api_caller
	}

	kb := bytes.TrimRight(body, "\x00")
	kbb := string(kb)
	// fmt.Println("Headers", filterHeader)

	// record incoming request
	infoReq := new(models.Info_req)
	(*infoReq).Url = url
	(*infoReq).Queryparam = queryparam
	(*infoReq).ClientIp = clientIp
	(*infoReq).ClientPort = clientPort
	(*infoReq).ServerPort = getServerPort()
	(*infoReq).IsGrpc = false
	(*infoReq).HeaderMap = filterHeader
	(*infoReq).GrpcByte = make([][]byte, 0)
	(*infoReq).Method = method
	(*infoReq).Body = kbb
	(*infoReq).Protocol = protocol
	(*infoReq).ContentType = getContentType(filterHeader)
	(*infoReq).K2TraceData = traceData
	(*infoReq).K2RequestIdentifier = k2RequestIdentifier
	(*infoReq).ServerName = serverName
	createFuzzFile(k2RequestIdentifier)
	k2i.Info.Secure.K2associate(infoReq)
	dura := time.Since(t)
	logger.Debugln("k2pre ServerHTTP took (ms):", (dura.Nanoseconds())/1000000)
}

// ---------------------------------------------------
// Func: K2preServeGrpc - interception of incoming request
// ---------------------------------------------------
func K2preServeGrpc(remoteAddr, localAddr string) {
	t := time.Now()
	if !K2OK("pre.ServeGrpc") {
		earlyHookExit("pre.ServeGrpc")
		return
	}

	clientIp := ""
	clientPort := ""
	serverPort := ""

	if remoteAddr != "" {
		clientIp, clientPort = getIpAndPort(remoteAddr)
	}
	if localAddr != "" {
		_, serverPort = getIpAndPort(localAddr)
		//TODO check empty test case
	}
	if clientIp == "::1" {
		clientIp = "127.0.0.1"
	}
	infoReq := new(models.Info_req)
	(*infoReq).Url = ""
	(*infoReq).Queryparam = make(map[string][]string, 0)
	(*infoReq).HeaderMap = make(map[string]string)
	(*infoReq).GrpcByte = make([][]byte, 0)
	(*infoReq).Body = ""
	(*infoReq).Method = "gRPC"
	(*infoReq).ClientIp = clientIp
	(*infoReq).ClientPort = clientPort
	(*infoReq).ServerPort = serverPort
	(*infoReq).IsGrpc = true
	(*infoReq).Protocol = "gRPC"
	k2i.Info.Secure.K2associate(infoReq)
	dura := time.Since(t)
	logger.Debugln("k2pre ServerHTTP took (ms):", (dura.Nanoseconds())/1000000)
}

func K2associateHeader(hdrMap map[string]string) {
	t := time.Now()
	if !K2OK("pre.associateHeader") {
		earlyHookExit("pre.K2associateHeader")
		return
	}
	grpcRequestWithHeader(hdrMap)
	//k2i.Info.Secure.K2associateHeader(hdrMap)
	dura := time.Since(t)
	logger.Debugln("k2pre K2associateHeader took (ms):", (dura.Nanoseconds())/1000000)
}

func K2associateQueryParam(body interface{}, data []byte) {

	t := time.Now()
	if !K2OK("proto.codec.Unmarshal") {
		earlyHookExit("proto.codec.Unmarshal")
		return
	}
	k2i.Info.Secure.K2associateQueryParam(body, data)

	dura := time.Since(t)
	logger.Debugln("k2pre K2associateQueryParam took (ms):", (dura.Nanoseconds())/1000000)
}

func K2associateGrpcByte(data []byte) {

	t := time.Now()
	if !K2OK("pre.K2associateGrpcByte") {
		earlyHookExit("pre.K2associateGrpcByte")
		return
	}
	length := len(data)
	slc2 := make([]byte, length)
	copy(slc2, data)
	if k2i.Info.Secure.IsRequest() {
		k2i.Info.Secure.K2associateGrpcByte(slc2)
	} else {
		grpcRequestWithHeader(make(map[string]string))
		k2i.Info.Secure.K2associateGrpcByte(slc2)
	}
	dura := time.Since(t)
	logger.Debugln("k2pre K2associateGrpcByte took (ms):", (dura.Nanoseconds())/1000000)
}

func K2grpcResponse(service, method, reply string) {
	t := time.Now()
	if !K2OK("grpc.Response") {
		earlyHookExit("grpc.Response")
		return
	}
	logger.Infoln("intercept grpc.Response: service", service, ",method:", method, ",args:", reply)
	//TODO - grpc Response analysis for XSS
	k2i.Info.Secure.K2dissociate()
	dura := time.Since(t)
	logger.Debugln("k2pre grpc.Response took (ms):", (dura.Nanoseconds())/1000000)
}

func K2dissociate() {
	k2i.Info.Secure.K2dissociate()
	removeFuzzFile()
}

func XssCheck() {
	t := time.Now()
	if !K2OK("response.Write") {
		earlyHookExit("response.Write")
		return
	}
	r := k2i.Info.Secure.K2getRequest()
	if r != nil && r.ResponseBody != "" {
		//logger.Debugln("k2 responseBody : " + r.ResponseBody)

		out := k2Utils.CheckForReflectedXSS(r)
		logger.Debugln("CheckForReflectedXSS out value is : ", out)

		if len(out) == 0 && (k2i.Info.GlobalData.VulnerabilityScan.Enabled && k2i.Info.GlobalData.VulnerabilityScan.IastScan.Enabled) == false {
			logger.Debugln("No need to send xss event as not attack and dynamic scanning is false")
		} else {
			logger.Debugln("return value of reflected xss string : ", out)
			calledID := increaseCount()
			var arg []string
			arg = append(arg, out)
			arg = append(arg, r.ResponseBody)
			k2i.Info.Secure.SendEvent(calledID, "REFLECTED_XSS", arg)
		}

		logger.Debugln("Called check for reflected XSS" + out)
	}
	dura := time.Since(t)
	logger.Debugln("k2 responseBody took (ms):", (dura.Nanoseconds())/1000000)
}

func K2responseBody(b string) {
	t := time.Now()
	if !K2OK("response.Write") {
		earlyHookExit("response.Write")
		return
	}
	r := k2i.Info.Secure.K2getRequest()
	if r != nil {
		r.ResponseBody = r.ResponseBody + b
		k2i.Info.Secure.K2calculateApiId()
	}
	dura := time.Since(t)
	logger.Debugln("k2 responseBody took (ms):", (dura.Nanoseconds())/1000000)
}

func currentURL() string {
	r := k2i.Info.Secure.K2getRequest()
	if r == nil {
		return ""
	}
	return (*r).Url
}

func K2openFile(fname string, flag int) *models.EventJson {
	if k2Utils.CaseInsensitiveContains(fname, k2i.Info.ApplicationInfo.AppUUID) {
		// here dont put logger, will cause issue with logrus and hook
		//the hook is for log file rotation, ignore
		return nil
	}
	if !K2OK("pre.openFile") {
		earlyHookExit(" OpenFile notOK or name-empty")
		return nil
	}
	if len(fname) < 1 || fname == "/dev/null" {
		return nil
	}
	eventId := increaseCount()
	var args []string

	args = append(args, fname)
	if fileModified(flag) && fileInApp(fname) && fileCanExecute(fname) {
		return k2i.Info.Secure.SendEvent(eventId, "FILE_INTEGRITY", args)
	} else {
		return k2i.Info.Secure.SendEvent(eventId, "FILE_OPERATION", args)
	}
}
func K2RemoveFile(name string) *models.EventJson {
	if !K2OK("pre.openFile") {
		earlyHookExit(" OpenFile notOK or name-empty")
		return nil
	}
	if len(name) < 1 || name == "/dev/null" {
		return nil
	}
	eventId := increaseCount()
	var args []string
	args = append(args, name)
	return k2i.Info.Secure.SendEvent(eventId, "FILE_OPERATION", args)
}

func K2preCommand(q string) *models.EventJson {
	if !K2OK("pre.Command") {
		earlyHookExit(" Command")
		return nil
	}
	calledID := increaseCount()
	var arg []string
	arg = append(arg, q)
	return k2i.Info.Secure.SendEvent(calledID, "SYSTEM_COMMAND", arg)

}

func K2nosqlExec(f, g interface{}, qtype string) *models.EventJson {
	if !K2OK("pre.nosqlExec") {
		earlyHookExit(" nosqlExec")
		return nil
	}
	calledID := increaseCount()

	var arg11 []interface{}
	var arg12 []interface{}
	tmp_map := map[string]interface{}{
		"filter":  f,
		"options": g,
	}
	arg11 = append(arg11, tmp_map)
	tmp_map1 := map[string]interface{}{
		"payloadType": qtype,
		"payload":     arg11,
	}

	arg12 = append(arg12, tmp_map1)
	return k2i.Info.Secure.SendEvent(calledID, "NOSQL_DB_COMMAND", arg12)

}

func K2dbquery(q string, args ...interface{}) *models.EventJson {
	if !K2OK("pre.dbQuery") {
		earlyHookExit(" dbQuery")
		return nil
	}
	eventId := increaseCount()

	var arg11 []interface{}
	parameters := map[int]interface{}{}
	for i := range args {
		str := fmt.Sprintf("%v", args[i])
		parameters[i] = string(str)
	}
	tmp_map := map[string]interface{}{
		"query":      q,
		"parameters": parameters,
	}
	arg11 = append(arg11, tmp_map)

	return k2i.Info.Secure.SendEvent(eventId, "SQL_DB_COMMAND", arg11)
}

func K2dbprepare(q, p string) {
	t := time.Now()
	if !K2OK("pre.dbPrepare") {
		earlyHookExit(" dbPrepare")
		return
	}
	k2i.Info.Secure.K2dbprepare(q, p)
	dura := time.Since(t)
	logger.Debugln("k2pre dbprepare took (ms):", (dura.Nanoseconds() / 1000000))
}

func K2dbexecprepare(q_address string, args ...interface{}) *models.EventJson {
	if !K2OK("pre.dbQuery") {
		earlyHookExit(" dbQuery")
		return nil
	}
	calledID := increaseCount()
	return k2i.Info.Secure.K2dbexecprepare(calledID, q_address, args...)
}

func K2xpathEval(a string) *models.EventJson {
	if !K2OK("pre.xpathEval") {
		return nil
	}
	calledID := increaseCount()
	var arg []string
	arg = append(arg, a)
	return k2i.Info.Secure.SendEvent(calledID, "XPATH", arg)
}

func K2ldap(a map[string]string) *models.EventJson {
	if !K2OK("pre.ldapSearch") {
		return nil
	}
	calledID := increaseCount()
	var arg []interface{}
	arg = append(arg, a)
	return k2i.Info.Secure.SendEvent(calledID, "LDAP", arg)
}

func K2EvalJS(a string) *models.EventJson {
	if !K2OK("EvalJS") {
		return nil
	}
	calledID := increaseCount()
	var arg []string
	arg = append(arg, EscapeString(a))

	return k2i.Info.Secure.SendEvent(calledID, "JAVASCRIPT_INJECTION", arg)
}

// ---------------------------------------------------
// func: K2preExit interception of process exit
// ---------------------------------------------------
func K2preExit(code int) {
	t := time.Now()
	if !K2OK("pre.Exit") {
		return
	}
	k2i.Info.Secure.K2preExit(code)
	dura := time.Since(t)
	logger.Debugln("k2pre Exit took (ms):", (dura.Nanoseconds() / 1000 / 1000))
}

// ---------------------------------------------------
// func: K2PortDetection for to detect server port
// ---------------------------------------------------
func K2PortDetection(data string) {

	ip, port := getIpAndPort(data)

	if ip == "::" || ip == "" {
		ip = "localhost"
	}
	logger.Infoln("Detected Port : ", port)
	logger.Infoln("Detected Server IP : ", ip)

	k2i.Info.ApplicationInfo.ServerIp = ip
	if port == "" {
		return
	}

	a, _ := strconv.Atoi(port)

	if !contains(k2i.Info.ApplicationInfo.Ports, a) {
		k2i.Info.ApplicationInfo.Ports = append(k2i.Info.ApplicationInfo.Ports, a)
	}
	//	k2secure_event.SendStartEvent()
}

func IsK2Disable() bool {
	return k2i.Info.IsK2Disable
}

func K2ProcessWSInit(server_name string) {
	go k2ws.K2Init(server_name)
}

func K2FastHttpData(c net.Conn) {
	k2i.Info.Secure.K2associateFastHttpData(c)
}
func K2RemoveFastHttpData() {
	k2i.Info.Secure.K2RemoveFastHttpData()
}
func K2GetFastHttpData() net.Conn {
	return k2i.Info.Secure.K2GetFastHttpData()
}

func K2GrpcData(remoteAddr string) {
	t := time.Now()
	if !K2OK("pre.ServeGrpc") {
		earlyHookExit("pre.ServeGrpc")
		return
	}

	clientIp := ""
	clientPort := ""
	if remoteAddr != "" {
		clientIp, clientPort = getIpAndPort(remoteAddr)
	}
	infoReq := new(models.Info_grpc)

	(*infoReq).ClientIp = clientIp
	(*infoReq).ClientPort = clientPort
	k2i.Info.Secure.K2associateGrpcData(infoReq)
	dura := time.Since(t)
	logger.Debugln("k2pre K2GrpcData took (ms):", (dura.Nanoseconds() / 1000000))

}

func K2RemoveGrpcData() {
	k2i.Info.Secure.K2delGrpcData()
}

func GetTraceHeader(id *models.EventJson) (string, string) {

	return k2i.Info.Secure.K2getTraceHeader(id)

}

func GetApiCaller(url string) string {
	port := ""
	if k2i.Info.ApplicationInfo.Ports != nil && len(k2i.Info.ApplicationInfo.Ports) > 0 {
		port = k2Utils.IntToString(k2i.Info.ApplicationInfo.Ports[0])
	}
	url = cannonicalURL(url)
	durl := base64.StdEncoding.EncodeToString([]byte(url))
	id := fmt.Sprintf("%s||%s||%s||%s", k2i.Info.ApplicationInfo.AppUUID, k2i.Info.ApplicationInfo.ContextPath, port, durl)
	return id
}

func GetFuzzHeader() string {
	return k2i.Info.Secure.GetFuzzHeader()
}

// --------------------------------------------------
// Func k2CallerId - identify CallerFunction,file,line
// --------------------------------------------------
func K2CallerId(f int) k2i.Tuple {
	return k2i.K2CallerId(f + 1)
}

// --------------------------------------------------
// Func k2FuncId - identify function,file,line
// --------------------------------------------------
func K2FuncId(pc interface{}) k2i.Tuple {
	return k2i.K2FuncId(pc)
}

func getIpAndPort(data string) (string, string) {
	var port = ""
	var ip = ""
	if data == "" {
		return ip, port
	}

	index := strings.LastIndex(data, ":")
	if index < 0 {
		return ip, port
	}
	port = data[index+1:]
	tmpIp := data[:index]
	index = strings.Index(tmpIp, ":")
	if index < 0 {
		return tmpIp, port
	}
	tmpIp = tmpIp[1 : len(tmpIp)-1]
	index = strings.Index(tmpIp, "%")
	//fmt.Println(index)
	if index < 0 {
		return tmpIp, port
	}
	tmpIp = tmpIp[:index]
	return tmpIp, port
}

func contains(ports []int, port int) bool {
	for _, a := range ports {
		if a == port {
			return true
		}
	}
	return false
}

func getServerPort() string {
	if k2i.Info.ApplicationInfo.Ports != nil && len(k2i.Info.ApplicationInfo.Ports) > 0 {
		return strconv.Itoa(k2i.Info.ApplicationInfo.Ports[0])
	}
	return ""
}

func InitSyms() {
	k2i.Info.Secure.InitSyms()
}
func getContentType(header map[string]string) string {

	for key, v := range header {
		if k2Utils.CaseInsensitiveEquals(key, "Content-type") {
			return v
		}
	}
	return ""
}
func grpcRequestWithHeader(header map[string]string) {
	t := time.Now()
	if !K2OK("pre.ServeGrpc") {
		earlyHookExit("pre.ServeGrpc")
		return
	}
	infoReq := new(models.Info_req)
	(*infoReq).Url = ""
	(*infoReq).Queryparam = make(map[string][]string, 0)
	(*infoReq).GrpcByte = make([][]byte, 0)
	(*infoReq).Method = "gRPC"
	(*infoReq).Body = "kbb"
	(*infoReq).ClientIp = ""
	(*infoReq).ClientPort = ""
	(*infoReq).ServerPort = getServerPort()
	(*infoReq).IsGrpc = true
	host := ""
	api_caller := ""
	for k, v := range header {

		if k == ":method" {
			(*infoReq).Method = v
		} else if k == ":path" {
			(*infoReq).Url = v
		} else if k == ":scheme" {
			(*infoReq).Protocol = v
		} else if k == "content-type" {
			(*infoReq).ContentType = v
		} else if k2Utils.CaseInsensitiveEquals(k, "K2-TRACING-DATA") {
			(*infoReq).K2TraceData = v
			delete(header, k)
		} else if k2Utils.CaseInsensitiveEquals(k, "k2-fuzz-request-id") {
			(*infoReq).K2RequestIdentifier = v
			delete(header, k)
		} else if k2Utils.CaseInsensitiveEquals(k, ":authority") {
			(*infoReq).ServerName = k
		} else if k2Utils.CaseInsensitiveEquals(k, ":host") {
			host = k
		} else if k2Utils.CaseInsensitiveEquals(k, "K2-API-CALLER") {
			api_caller = v
			delete(header, k)
		}
	}
	if (*infoReq).K2TraceData != "" {
		header["K2-TRACING-DATA"] = (*infoReq).K2TraceData
	}
	if (*infoReq).K2RequestIdentifier != "" {
		header["K2-FUZZ-REQUEST-ID"] = (*infoReq).K2RequestIdentifier
	}
	if api_caller != "" {
		header["K2-API-CALLER"] = api_caller
	}
	createFuzzFile((*infoReq).K2RequestIdentifier)
	if (*infoReq).ServerName == "" {
		(*infoReq).ServerName = host
	}
	(*infoReq).HeaderMap = header
	k2i.Info.Secure.K2associate(infoReq)
	dura := time.Since(t)
	logger.Debugln("k2pre ServerHTTP took (ms):", (dura.Nanoseconds())/1000000)
}

func SendExitEvent(event *models.EventJson, err error) {
	if err == nil && event != nil {
		k2i.Info.Secure.SendExitEvent(event)
	}
}

func increaseCount() string {

	eventCount := atomic.LoadUint64(&k2i.Info.HookCalledCount)
	atomic.AddUint64(&k2i.Info.HookCalledCount, 1)
	return strconv.FormatUint(eventCount, 10)

}

func fileModified(flag int) bool {
	return ((flag & syscall.O_RDWR) | (flag & syscall.O_WRONLY) | (flag & syscall.O_CREAT) | (flag & syscall.O_APPEND)) != 0
}

func fileInApp(fn string) bool {

	// file get abs path
	w := fn
	logger.Debugln("fileInApp:w=", fn)
	wi := k2i.Info.EnvironmentInfo.Wd

	logger.Debugln("fileInApp:cwd=", wi)
	if !strings.HasPrefix(w, wi) {
		logger.Debugln("fileInApp: prefix did not match:" + w + "," + wi)
		w, _ = filepath.Abs(fn)
		logger.Debugln("fileInApp: using abs path:" + w + "," + wi)
		if !strings.HasPrefix(w, wi) {
			logger.Debugln("fileInApp: prefix did not match:" + w + "," + wi)
			if w2, e1 := os.Lstat(w); (e1 == nil) && (w2.Mode()&os.ModeSymlink != 0) {
				if wx, e2 := os.Readlink(w); e2 != nil {
					logger.Debugln("fileInApp: readlink", wx)
					w = wx
					if !strings.HasPrefix(w, wi) {
						logger.Debugln("fileInApp: prefix did not match:" + w + "," + wi)
						return false
					}
				} else {
					return false
				}
			} else {
				return false
			}
		}
		//true
	}
	logger.Debugln("fileInApp:", fn, w, "TRUE")
	return true
}

func fileExecByExtension(fn string) bool {
	s := []string{".jar", ".py", ".sh", ".ksh", ".rb", ".php", ".py",
		".js", ".so", ".go" /* exec(go build downloaded.go) exec ./downloaded*/}
	for _, v := range s {
		if strings.HasSuffix(fn, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------
// Func: fileIsBinaryExecutable
// ---------------------------------------------------
func fileIsBinaryExec(fn string) bool {
	//file is ELF - .so or full executable
	f, e := os.Open(fn)
	if e != nil {
		return false
	}
	_, e = elf.NewFile(f)
	f.Close()
	if e == nil {
		return true
	}
	return false
}
func fileCanExecute(fn string) bool {
	return fileExecByExtension(fn) || fileIsBinaryExec(fn)
}

func EscapeString(q string) string {
	r := q
	r = strings.Replace(r, "\"", "\\\"", -1)
	r = strings.Replace(r, "\r", "\\r", -1)
	r = strings.Replace(r, "\n", "\\n", -1)
	if r != q {
		logger.Debugln("EscapeString:", q, " -> ", r)
	}
	return r

}

func createFuzzFile(fuzzheaders string) {
	DSON := true
	if DSON && fuzzheaders != "" {
		additionalData := strings.Split(fuzzheaders, K2_SEP)
		logger.Debugln("additionalData:", additionalData)
		if len(additionalData) >= 7 {
			for i := 6; i < len(additionalData); i++ {
				fileName := additionalData[i]
				fileName = strings.Replace(fileName, "{{K2_HOME_TMP}}", k2i.CVE_TAR_SPACE, -1)
				fileName = strings.Replace(fileName, "%7B%7BK2_HOME_TMP%7D%7D", k2i.CVE_TAR_SPACE, -1)
				dir := filepath.Dir(fileName)
				if dir != "" {
					os.MkdirAll(dir, os.ModePerm)
				}
				emptyFile, err := os.Create(fileName)
				if err != nil {
					logger.Errorln("Error while creating file : ", err.Error(), fileName)
				}
				emptyFile.Close()
			}
		}
	}
}

func removeFuzzFile() {
	fuzzheaders := k2i.Info.Secure.GetFuzzHeader()
	if k2i.Info.GlobalData.VulnerabilityScan.Enabled && k2i.Info.GlobalData.VulnerabilityScan.IastScan.Enabled && fuzzheaders != "" {
		additionalData := strings.Split(fuzzheaders, K2_SEP)
		logger.Debugln("additionalData:", additionalData)
		if len(additionalData) >= 7 {
			for i := 6; i < len(additionalData); i++ {
				fileName := additionalData[i]
				fileName = strings.Replace(fileName, "{{K2_HOME_TMP}}", k2i.CVE_TAR_SPACE, -1)
				fileName = strings.Replace(fileName, "%7B%7BK2_HOME_TMP%7D%7D", k2i.CVE_TAR_SPACE, -1)
				err := os.Remove(fileName)
				if err != nil {
					logger.Errorln("Error while removing created file : ", err.Error(), fileName)
				}
			}
		}
	}
}

func GetLogger(loggerName string) *logrus.Entry {
	return logging.GetLogger(loggerName)
}

func IsHookedLog(name string, e error) {
	logging.IsHooked(name, e)
}
func GetDummyEvent() *models.EventJson {
	var dummy *models.EventJson
	return dummy
}

func IsFileExist(name string) bool {
	return k2Utils.IsFileExist(name)
}
func cannonicalURL(urlx string) string {
	u, e := url.Parse(urlx)
	if e != nil {
		return urlx
	}
	u.RawQuery = ""
	s := u.String()
	if s == "" {
		return urlx
	}
	return s
}
func CheckApiBlockingNeeded(apiId string) bool {
	if !(k2i.Info.GlobalData.ProtectionMode.Enabled && k2i.Info.GlobalData.ProtectionMode.APIBlocking.Enabled) {
		return false
	}

	if k2Utils.Contains(k2i.Info.GlobalPolicy.AllowedApis, apiId) {
		return false
	}

	if k2Utils.Contains(k2i.Info.GlobalPolicy.BlockedApis, apiId) {
		return true
	}
	return k2i.Info.GlobalData.ProtectionMode.APIBlocking.ProtectAllApis
}

func CheckIPBlockingNeeded(apiId string) bool {
	if !(k2i.Info.GlobalData.ProtectionMode.Enabled && k2i.Info.GlobalData.ProtectionMode.IPBlocking.Enabled) {
		return false
	}

	if k2Utils.Contains(k2i.Info.GlobalPolicy.AllowedIps, apiId) {
		return false
	}

	if k2Utils.Contains(k2i.Info.GlobalPolicy.BlockedIps, apiId) {
		return true
	}
	return false
}

func GetAttackerPage(apiId string) string {
	page := k2Utils.GetApiBlockingPage()
	return strings.Replace(page, "{{ID}}", apiId, 1)
}
func GetAttackerPageIP(ip string) string {
	page := k2Utils.GetipBlockingPage()
	return strings.Replace(page, "{{ID}}", ip, 1)
}

func GetIp(data string, header map[string][]string) string {
	ip, _ := getIpAndPort(data)
	if k2i.Info.GlobalData.ProtectionMode.IPBlocking.AttackerIPBlocking && k2i.Info.GlobalData.ProtectionMode.IPBlocking.IPDetectViaXFF {
		for k, v := range header {
			if k2Utils.CaseInsensitiveEquals(k, "x-forwarded-for") {
				ip = strings.Split(strings.Join(v, ","), ",")[0]
				break
			}
		}
	}
	return ip
}

func UpdateBlockingCounter(eventID, apiId string, isBlocked bool) {
	k2i.Info.Secure.K2associateBlockingResponse(eventID, apiId, isBlocked)
}

func IsBlockedAPI(event *models.EventJson) bool {
	if event == nil {
		return false
	}
	if !k2i.Info.GlobalData.ProtectionMode.Enabled && k2i.Info.GlobalData.ProtectionMode.APIBlocking.Enabled {
		return false
	}
	return k2i.Info.Secure.K2IsApiBlocked(event.ID)
}
func IsBlockedHttp() (bool, string) {
	return k2i.Info.Secure.K2IsHttpBlocked()
}
