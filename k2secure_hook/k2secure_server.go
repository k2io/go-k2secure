// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

type K2HandlerFunc struct{}

//go:noinline
func (k *K2HandlerFunc) ServeHTTP_s(rw http.ResponseWriter, req *http.Request) {
	logger.Debugln("Hook Called : ", "net/http.serverHandler.ServeHTTP_s")
	if req != nil {
		proto := ""
		serverName := ""
		if req.TLS == nil {
			proto = "http"
		} else {
			proto = "https"
			serverName = req.TLS.ServerName
		}
		k2buf := make([]byte, 0)
		k2Hosthdr := req.RemoteAddr
		var k2bb bytes.Buffer
		k2r := io.TeeReader(req.Body, &k2bb)

		if k2r != nil {
			k2buf2, k2e2 := ioutil.ReadAll(k2r)
			if k2e2 == nil {
				k2buf = k2buf2
			}
			r := ioutil.NopCloser(bytes.NewBuffer(k2buf))
			req.Body = r
		}
		queryparam := map[string][]string{}
		for key, value := range req.URL.Query() {
			queryparam[key] = value
		}
		k2i.K2preServeHTTP(req.URL.String(), k2Hosthdr, req.Header, req.Method, k2buf, queryparam, proto, serverName)
	}
	k.ServeHTTP_s(rw, req)
	k2i.XssCheck()
	k2i.K2dissociate()
	return
}

//go:noinline
func (k *K2HandlerFunc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger.Debugln("Hook Called : ", "net/http.serverHandler.ServeHTTP")
	if req != nil {
		proto := ""
		serverName := ""
		if req.TLS == nil {
			proto = "http"
		} else {
			proto = "https"
			serverName = req.TLS.ServerName
		}
		k2buf := make([]byte, 0)
		k2Hosthdr := req.RemoteAddr
		var k2bb bytes.Buffer
		k2r := io.TeeReader(req.Body, &k2bb)

		if k2r != nil {
			k2buf2, k2e2 := ioutil.ReadAll(k2r)
			if k2e2 == nil {
				k2buf = k2buf2
			}
			r := ioutil.NopCloser(bytes.NewBuffer(k2buf))
			req.Body = r
		}
		queryparam := map[string][]string{}
		for key, value := range req.URL.Query() {
			queryparam[key] = value
		}
		clientIp := k2i.GetIp(k2Hosthdr, req.Header)
		isBlocked := k2i.CheckIPBlockingNeeded(clientIp)
		if isBlocked {
			rw.Write([]byte(k2i.GetAttackerPageIP(clientIp)))
			return
		}
		k2i.K2preServeHTTP(req.URL.String(), k2Hosthdr, req.Header, req.Method, k2buf, queryparam, proto, serverName)
	}
	k.ServeHTTP_s(rw, req)
	k2i.XssCheck()
	ib, api := k2i.IsBlockedHttp()
	if ib {
		rw.Write([]byte(k2i.GetAttackerPage(api)))
	}
	k2i.K2dissociate()
	return
}

type K2WriteFunc struct{}

//go:noinline
func (k *K2WriteFunc) Write_s(lenData int, dataB []byte, dataS string) (n int, err error) {
	logger.Debugln("Hook Called : ", "net/http.(*response).write_s")
	if len(dataB) > 0 {
		k2i.K2responseBody(string(dataB))
	}
	if len(dataS) > 0 {
		k2i.K2responseBody(dataS)
	}
	a, e := k.Write_s(lenData, dataB, dataS)
	return a, e
}

//go:noinline
func (k *K2WriteFunc) Write(lenData int, dataB []byte, dataS string) (n int, err error) {
	logger.Debugln("Hook Called : ", "net/http.(*response).write")
	if len(dataB) > 0 {
		k2i.K2responseBody(string(dataB))
	}
	if len(dataS) > 0 {
		k2i.K2responseBody(dataS)
	}
	a, e := k.Write_s(lenData, dataB, dataS)
	return a, e
}

type K2ServeStruct struct {
	http.Server
}

//go:noinline
func (k *K2ServeStruct) k2Server_s(l net.Listener) error {
	logger.Debugln("Hook Called : ", "(*http.Server).Serve_s")
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString:", ipString)
		k2i.K2PortDetection(ipString)
	}
	k2i.K2ProcessWSInit("net/http")
	e := k.k2Server_s(l)
	return e
}

//go:noinline
func (k *K2ServeStruct) k2Server(l net.Listener) error {
	logger.Debugln("Hook Called : ", "(*http.Server).Serve")
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString:", ipString)
		k2i.K2PortDetection(ipString)
	}
	k2i.K2ProcessWSInit("net/http")
	e := k.k2Server_s(l)
	return e
}

type K2RequestFunc struct {
	http.Client
}

//go:noinline
func (k *K2RequestFunc) K2NewRequestWithContext_s(req *http.Request) (retres *http.Response, reterr error) {
	if req != nil {
		logger.Debugln("Hook Called : ", "http.Client.Do_s")
		logger.Debugln("------------ URL", req.URL)
		logger.Debugln("------------ Host", req.Host)
		logger.Debugln("------------ Method", req)
		var url = req.URL.String()
		var host = req.Host // replace with destinationIp

		var port = "80" //destinationPort

		if url != "" {
			k2i.K2request(url, host, port, false, req.Header)
		}
	}
	a, e := k.K2NewRequestWithContext_s(req)
	return a, e
}

//go:noinline
func (k *K2RequestFunc) K2NewRequestWithContext(req *http.Request) (retres *http.Response, reterr error) {

	if k == nil {
		logger.Debugln("SSRF HOOK client = nil")
	}
	var eventID *models.EventJson
	if req != nil {
		logger.Debugln("Hook Called : ", "http.Client.Do")
		logger.Debugln("------------ URL", req.URL)
		logger.Debugln("------------ Host", req.Host)
		logger.Debugln("------------ Method", req.Method)
		var url = req.URL.String()
		var host = req.Host // replace with destinationIp

		var port = "80" //destinationPort

		if url != "" {
			eventID = k2i.K2request(url, host, port, false, req.Header)
			if k2i.IsBlockedAPI(eventID) {
				return nil, k2i.K2Exception()
			}
		}
		if eventID != nil {
			key, value := k2i.GetTraceHeader(eventID)
			logger.Debugln("k2 tracing data : ", value)
			if key != "" {
				req.Header.Add(key, value)
			}
		}
		value := k2i.GetApiCaller(url)
		req.Header.Add("K2-API-CALLER", value)
		value = k2i.GetFuzzHeader()
		if value != "" {
			req.Header.Add("k2-fuzz-request-id", value)
		}
	}
	a, e := k.K2NewRequestWithContext_s(req)
	k2i.SendExitEvent(eventID, e)
	return a, e
}

func initServerHook() {
	if !debug_drop_incoming_hooks {
		_, e := k2i.HookWrapRawNamed("net/http.serverHandler.ServeHTTP", (*K2HandlerFunc).ServeHTTP, (*K2HandlerFunc).ServeHTTP_s)
		logging.IsHooked("net/http.serverHandler.ServeHTTP", e)

		_, e = k2i.HookWrapRawNamed("net/http.(*response).write", (*K2WriteFunc).Write, (*K2WriteFunc).Write_s)
		logging.IsHooked("net/http.(*response).write", e)

		e = k2i.HookWrapInterface((*http.Server).Serve, (*K2ServeStruct).k2Server, (*K2ServeStruct).k2Server_s)
		logging.IsHooked("(*http.Server).Serve", e)
	}
	if !debug_drop_outgoing_hooks {
		_, e := k2i.HookWrapRawNamed("net/http.(*Client).do", (*K2RequestFunc).K2NewRequestWithContext, (*K2RequestFunc).K2NewRequestWithContext_s)
		logging.IsHooked("(*http.Client).do", e)
	}
}
