// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_fasthttpwrap

import (
	"bufio"
	"crypto/tls"
	"net"
	"reflect"

	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	"github.com/valyala/fasthttp"
)

var logger = k2i.GetLogger("fasthttp")

type k2Request struct {
	fasthttp.Request
}
type k2Server struct {
	fasthttp.Server
}

type k2Response struct {
	fasthttp.Response
}

type connTLSer interface {
	Handshake() error
	ConnectionState() tls.ConnectionState
}

//go:noinline
func (s *k2Server) k2Serve(ln net.Listener) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.Serve")

	if ln != nil {
		ipString := ln.Addr().String()
		logger.Debugln("ipString:", ipString)
		k2i.K2PortDetection(ipString)
	}
	k2i.K2ProcessWSInit("FastHTTP")
	return s.k2Serve_s(ln)
}

//go:noinline
func (s *k2Server) k2Serve_s(ln net.Listener) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.Serve")

	if ln != nil {
		ipString := ln.Addr().String()
		logger.Debugln("ipString:", ipString)
		k2i.K2PortDetection(ipString)
	}
	k2i.K2ProcessWSInit("FastHTTP")
	return s.k2Serve_s(ln)
}

func (s *k2Server) k2ServeConn(c net.Conn) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.k2ServeConn")
	k2i.K2FastHttpData(c)
	su := s.k2ServeConn_s(c)
	k2i.XssCheck()
	k2i.K2dissociate()
	k2i.K2RemoveFastHttpData()
	return su
}

func (s *k2Server) k2ServeConn_s(c net.Conn) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.k2ServeConn")
	k2i.K2FastHttpData(c)
	su := s.k2ServeConn_s(c)
	k2i.XssCheck()
	k2i.K2dissociate()
	k2i.K2RemoveFastHttpData()
	return su
}

//go:noinline
func (req *k2Request) K2ContinueReadBodyStream(r *bufio.Reader, maxBodySize int, preParseMultipartForm ...bool) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.ContinueReadBodyStream")
	err := req.K2ContinueReadBodyStream_s(r, maxBodySize, preParseMultipartForm...)
	headers := map[string][]string{}
	proto := "http"
	serverName := ""
	fv := reflect.ValueOf(req).Elem().FieldByName("isTLS")
	if fv.IsValid() {
		if fv.Bool() {
			proto = "https"
			conn := k2i.K2GetFastHttpData()
			if conn != nil {
				var a *net.TCPConn
				if reflect.TypeOf(conn) != reflect.TypeOf(a) {
					serverName = conn.(connTLSer).ConnectionState().ServerName
				}
			}
		}
	}
	if req != nil {
		req.Request.Header.VisitAll(func(key, value []byte) {
			var header []string
			header = append(header, string(value))
			headers[string(key)] = header

		})
		queryparam := map[string][]string{}
		req.URI().QueryArgs().VisitAll(func(key, value []byte) {
			var query []string
			query = append(query, string(value))
			queryparam[string(key)] = query

		})
		//serverName := ""
		conn := k2i.K2GetFastHttpData()
		logger.Debugln("type to conn ", reflect.TypeOf(conn))
		k2i.K2preServeHTTP(string(req.Request.RequestURI()), string(req.Request.Host()), headers, string(req.Request.Header.Method()), req.Request.Body(), queryparam, proto, serverName)
	}

	return err
}

//go:noinline
func (req *k2Request) K2ContinueReadBodyStream_s(r *bufio.Reader, maxBodySize int, preParseMultipartForm ...bool) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.ContinueReadBodyStream")
	err := req.K2ContinueReadBodyStream_s(r, maxBodySize, preParseMultipartForm...)
	headers := map[string][]string{}
	proto := "http"
	serverName := ""
	fv := reflect.ValueOf(req).Elem().FieldByName("isTLS")
	if fv.IsValid() {
		if fv.Bool() {
			proto = "https"
			conn := k2i.K2GetFastHttpData()
			if conn != nil {
				var a *net.TCPConn
				if reflect.TypeOf(conn) != reflect.TypeOf(a) {
					serverName = conn.(connTLSer).ConnectionState().ServerName
				}
			}
		}
	}
	if req != nil {
		req.Request.Header.VisitAll(func(key, value []byte) {
			var header []string
			header = append(header, string(value))
			headers[string(key)] = header

		})
		queryparam := map[string][]string{}
		req.URI().QueryArgs().VisitAll(func(key, value []byte) {
			var query []string
			query = append(query, string(value))
			queryparam[string(key)] = query

		})
		//serverName := ""
		conn := k2i.K2GetFastHttpData()
		logger.Debugln("type to conn ", reflect.TypeOf(conn))
		k2i.K2preServeHTTP(string(req.Request.RequestURI()), string(req.Request.Host()), headers, string(req.Request.Header.Method()), req.Request.Body(), queryparam, proto, serverName)
	}

	return err
}

//go:noinline
func (req *k2Request) K2ContinueReadBody(r *bufio.Reader, maxBodySize int, preParseMultipartForm ...bool) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.ContinueReadBody")
	fv := reflect.ValueOf(req).Elem().FieldByName("isTLS")
	proto := "http"
	serverName := ""
	if fv.IsValid() {
		if fv.Bool() {
			proto = "https"
			conn := k2i.K2GetFastHttpData()
			if conn != nil {
				var a *net.TCPConn
				if reflect.TypeOf(conn) != reflect.TypeOf(a) {
					serverName = conn.(connTLSer).ConnectionState().ServerName
				}
			}
		}
	}
	err := req.K2ContinueReadBody_s(r, maxBodySize, preParseMultipartForm...)
	headers := map[string][]string{}
	if req != nil {
		req.Request.Header.VisitAll(func(key, value []byte) {
			var header []string
			header = append(header, string(value))
			headers[string(key)] = header

		})
		queryparam := map[string][]string{}
		req.URI().QueryArgs().VisitAll(func(key, value []byte) {
			var query []string
			query = append(query, string(value))
			queryparam[string(key)] = query

		})
		conn := k2i.K2GetFastHttpData()
		logger.Debugln("type to conn ", reflect.TypeOf(conn))
		k2i.K2preServeHTTP(string(req.Request.RequestURI()), string(req.Request.Host()), headers, string(req.Request.Header.Method()), req.Request.Body(), queryparam, proto, serverName)
	}
	return err
}

//go:noinline
func (req *k2Request) K2ContinueReadBody_s(r *bufio.Reader, maxBodySize int, preParseMultipartForm ...bool) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.ContinueReadBody_s")
	fv := reflect.ValueOf(req).Elem().FieldByName("isTLS")
	proto := "http"
	serverName := ""
	if fv.IsValid() {
		if fv.Bool() {
			proto = "https"
			conn := k2i.K2GetFastHttpData()
			if conn != nil {
				var a *net.TCPConn
				if reflect.TypeOf(conn) != reflect.TypeOf(a) {
					serverName = conn.(connTLSer).ConnectionState().ServerName
				}
			}
		}
	}
	err := req.K2ContinueReadBody_s(r, maxBodySize, preParseMultipartForm...)
	headers := map[string][]string{}
	if req != nil {
		req.Request.Header.VisitAll(func(key, value []byte) {
			var header []string
			header = append(header, string(value))
			headers[string(key)] = header

		})
		queryparam := map[string][]string{}
		req.URI().QueryArgs().VisitAll(func(key, value []byte) {
			var query []string
			query = append(query, string(value))
			queryparam[string(key)] = query

		})
		conn := k2i.K2GetFastHttpData()
		logger.Debugln("type to conn ", reflect.TypeOf(conn))
		k2i.K2preServeHTTP(string(req.Request.RequestURI()), string(req.Request.Host()), headers, string(req.Request.Header.Method()), req.Request.Body(), queryparam, proto, serverName)
	}
	return err
}

//go:noinline
func (resp *k2Response) K2Write(w *bufio.Writer) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.write")
	if resp != nil {
		k2i.K2responseBody(string(resp.Body()))
	}
	return resp.K2Write_s(w)
}

//go:noinline
func (resp *k2Response) K2Write_s(w *bufio.Writer) error {
	logger.Debugln("Hook Called : ", "*fasthttp.Server.write")
	if resp != nil {
		k2i.K2responseBody(string(resp.Body()))
	}
	return resp.K2Write_s(w)
}

func hook() {
	if k2i.DropHook_grpc() {
		return
	}
	logger.Infoln("fastHttp pluginStart")
	e := k2i.HookWrapInterface((*fasthttp.Request).ContinueReadBodyStream, (*k2Request).K2ContinueReadBodyStream, (*k2Request).K2ContinueReadBodyStream_s)
	k2i.IsHookedLog("(*fasthttp.Request).ContinueReadBodyStream", e)
	e = k2i.HookWrapInterface((*fasthttp.Request).ContinueReadBody, (*k2Request).K2ContinueReadBody, (*k2Request).K2ContinueReadBody_s)
	k2i.IsHookedLog("(*fasthttp.Request).ContinueReadBody", e)
	_, e = k2i.HookWrapRawNamed("github.com/valyala/fasthttp.(*Server).serveConn", (*k2Server).k2ServeConn, (*k2Server).k2ServeConn_s)
	k2i.IsHookedLog("(*fasthttp.Server).ServeConn", e)
	e = k2i.HookWrapInterface((*fasthttp.Response).Write, (*k2Response).K2Write, (*k2Response).K2Write_s)
	k2i.IsHookedLog("(*fasthttp.Response).Write", e)
	e = k2i.HookWrapInterface((*fasthttp.Server).Serve, (*k2Server).k2Serve, (*k2Server).k2Serve_s)
	k2i.IsHookedLog("(*fasthttp.Server).Serve", e)
	logger.Infoln("fastHttp pluginStart completed")

}
func init() {

	if k2i.K2OK("k2secure_fasthttp") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	hook()
}
