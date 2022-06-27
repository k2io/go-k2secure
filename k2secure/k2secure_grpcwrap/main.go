// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_grpcwrap

import (
	"context"
	"encoding/json"
	"net"

	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	k2secure_ws "github.com/k2io/go-k2secure/v2/k2secure_ws"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	_ "google.golang.org/protobuf/proto"
)

var logger = k2i.GetLogger("grpc")

// --------------------- RegisterService pair -------
type K2server struct {
	grpc.Server
}

type K2codec struct{}

func (k K2codec) Unmarshal(data []byte, v interface{}) error {
	logger.Debugln(" --- Unmarshal HOOKS hooked called --- ")

	a := k.Unmarshal_s(data, v)

	_, err := json.Marshal(v)
	if err != nil {
		logger.Errorln("error in Marshal Data in Grpc Unmarshal HOOKS")
	} else {

		k2i.K2associateQueryParam(v, data)
	}
	return a
}

//go:noinline
func (k K2codec) Unmarshal_s(data []byte, v interface{}) error {
	logger.Debugln(" --- Unmarshal HOOKS hooked called --- ")

	a := k.Unmarshal_s(data, v)

	_, err := json.Marshal(v)
	if err != nil {
		logger.Errorln("error in Marshal Data in Grpc Unmarshal HOOKS")
	} else {

		k2i.K2associateQueryParam(v, data)
	}
	return a

}

type K2serverFunc struct {
	grpc.Server
}

//go:noinline
func (k *K2serverFunc) handleRawConn_s(lisAddr string, rawConn net.Conn) {
	logger.Debugln("------------ handleRawConn_s----------")
	remoteAddr := ""
	localAddr := ""
	if rawConn != nil {
		remoteAddr = rawConn.RemoteAddr().String()
		localAddr = rawConn.LocalAddr().String()
	}
	k2i.K2preServeGrpc(remoteAddr, localAddr)
	k.handleRawConn_s(lisAddr, rawConn)
	k2i.K2dissociate()
	return
}

//go:noinline
func (k *K2serverFunc) handleRawConn(lisAddr string, rawConn net.Conn) {
	logger.Debugln("------------ handleRawConn----------")
	remoteAddr := ""
	localAddr := ""
	if rawConn != nil {
		remoteAddr = rawConn.RemoteAddr().String()
		localAddr = rawConn.LocalAddr().String()
	}
	k2i.K2preServeGrpc(remoteAddr, localAddr)
	k.handleRawConn_s(lisAddr, rawConn)
	k2i.K2dissociate()
	return
}

type K2Operateheader struct{}

//go:noinline
func (k *K2Operateheader) Operateheader_s(frame *http2.MetaHeadersFrame, handle func(*grpc.Stream), traceCtx func(context.Context, string) context.Context) (fatal bool) {
	logger.Debugln("------------ GRPC-Header_s---------")

	headers := frame.Fields

	if headers != nil {
		m := make(map[string]string)
		for _, hf := range frame.Fields {
			m[hf.Name] = hf.Value
			logger.Debugln("Header name : ", hf.Name)
			logger.Debugln("Header value : ", hf.Value)
		}

		k2i.K2associateHeader(m)
	} else {
		logger.Infoln("GRPC header is nil")
	}

	b := k.Operateheader_s(frame, handle, traceCtx)
	return b
}

//go:noinline
func (k *K2Operateheader) Operateheader(frame *http2.MetaHeadersFrame, handle func(*grpc.Stream), traceCtx func(context.Context, string) context.Context) (fatal bool) {
	logger.Debugln("------------ GRPC-Header---------")

	headers := frame.Fields

	if headers != nil {
		m := make(map[string]string)
		for _, hf := range frame.Fields {
			m[hf.Name] = hf.Value
			logger.Debugln("Header name : ", hf.Name)
			logger.Debugln("Header value : ", hf.Value)
		}

		k2i.K2associateHeader(m)
	} else {
		logger.Infoln("GRPC header is nil")
	}

	b := k.Operateheader_s(frame, handle, traceCtx)
	return b
}

type K2Parser struct{}

//go:noinline
func (k *K2Parser) RecvMsg_s(f *http2.DataFrame) {
	logger.Debugln("------------ GRPC-RecvMsg_s---------")
	if f.Data() != nil {
		logger.Debugln("------------ RecvMsg---------")
		logger.Debugln(f.Data())
		k2i.K2associateGrpcByte(f.Data())

	} else {
		logger.Infoln("GRPC data byte is nil")
	}
	k.RecvMsg_s(f)
	return
}

//go:noinline
func (k *K2Parser) RecvMsg(f *http2.DataFrame) {
	logger.Debugln("------------ GRPC-RecvMsg---------")
	if f.Data() != nil {
		logger.Debugln("------------ RecvMsg---------")
		logger.Debugln(f.Data())
		k2i.K2associateGrpcByte(f.Data())

	} else {
		logger.Infoln("GRPC data byte is nil")
	}
	k.RecvMsg_s(f)
	return
}

type K2ServeStructGrpc struct {
	grpc.Server
}

//go:noinline
func (k *K2ServeStructGrpc) k2Server_s(l net.Listener) error {
	logger.Debugln("------------ Port Detection_s----------")
	// K2 Process start
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString : ", ipString)
		k2i.K2PortDetection(ipString)
	}
	k2i.K2ProcessWSInit("GRPC")
	e := k.k2Server_s(l)
	return e
}

//go:noinline
func (k *K2ServeStructGrpc) k2Server(l net.Listener) error {
	logger.Debugln("------------ Port Detection----------")
	// K2 Process start
	if l != nil {
		ipString := l.Addr().String()
		logger.Debugln("ipString : ", ipString)
		k2i.K2PortDetection(ipString)
	}
	k2i.K2ProcessWSInit("gRPC")
	e := k.k2Server_s(l)
	return e
}

//go:noinline
func K2Invoke_s(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	logger.Debugln("------------K2Invoke_s---------")
	url := ""
	if cc != nil {
		url = cc.Target()
		host, port, _ := net.SplitHostPort(url)
		logger.Debugln("url : ", url, " host : ", host, " port : ", port, " method: ", method)
		url = url + method
		proto := "http"
		if url != "" {
			url = proto + "://" + url
			logger.Debugln("final url ", url)
			var dummy map[string][]string
			k2i.K2request(url, host, port, true, dummy)
		}
	}
	if ctx != nil {
		key, value := k2i.GetTraceHeader(nil)
		logger.Debugln("k2 tracing data : ", value)

		if key != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, key, value)
		}
		value = k2i.GetApiCaller(url)
		ctx = metadata.AppendToOutgoingContext(ctx, "K2-API-CALLER", value)
	}
	e := K2Invoke_s(ctx, method, req, reply, cc, opts...)
	return e
}

//go:noinline
func K2Invoke(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	logger.Debugln("------------K2Invoke---------")
	url := ""
	var eventID = k2i.GetDummyEvent()
	if cc != nil {
		url = cc.Target()
		host, port, _ := net.SplitHostPort(url)
		logger.Debugln("url : ", url, " host : ", host, " port : ", port, " method: ", method)
		url = url + method
		proto := "http"
		// k2m was not using prototype data so for now sending http as default prototype
		// fv := reflect.ValueOf(cc).Elem().FieldByName("dopts")
		// if fv.IsValid() {
		// 	fv1 := fv.FieldByName("insecure")
		// 	if fv1.IsValid() {
		// 		if !fv1.Bool() {
		// 			proto = "https"
		// 			logger.Debugln("proto : true")
		// 		} else {
		// 			logger.Debugln("proto : false")
		// 		}
		// 	}
		// }
		if url != "" {
			url = proto + "://" + url
			logger.Debugln("final url ", url)
			var dummy map[string][]string
			eventID = k2i.K2request(url, host, port, true, dummy)
		}
	}
	if ctx != nil {
		if eventID != nil {
			key, value := k2i.GetTraceHeader(eventID)
			logger.Debugln("k2 tracing data : ", value)

			if key != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, key, value)
			}
		}
		value := k2i.GetApiCaller(url)
		ctx = metadata.AppendToOutgoingContext(ctx, "K2-API-CALLER", value)
		value = k2i.GetFuzzHeader()
		if value != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "k2-fuzz-request-id", value)
		}
	}
	e := K2Invoke_s(ctx, method, req, reply, cc, opts...)
	k2i.SendExitEvent(eventID, e)
	return e
}

type ServerTransport interface {
	// HandleStreams receives incoming streams using the given handler.
	HandleStreams(func(*grpc.Stream), func(context.Context, string) context.Context)

	// WriteHeader sends the header metadata for the given stream.
	// WriteHeader may not be called on all streams.
	WriteHeader(s *grpc.Stream, md metadata.MD) error

	// Write sends the data for the given stream.
	// Write may not be called on all streams.
	Write(s *grpc.Stream, hdr []byte, data []byte, opts *interface{}) error

	// WriteStatus sends the status of a stream to the client.  WriteStatus is
	// the final call made on a stream and always occurs.
	WriteStatus(s *grpc.Stream, st *status.Status) error

	// Close tears down the transport. Once it is called, the transport
	// should not be accessed any more. All the pending streams and their
	// handlers will be terminated asynchronously.
	Close()

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	// Drain notifies the client this ServerTransport stops accepting new RPCs.
	Drain()

	// IncrMsgSent increments the number of message sent through this transport.
	IncrMsgSent()

	// IncrMsgRecv increments the number of message received through this transport.
	IncrMsgRecv()
}

//go:noinline
func (s *K2ServeStructGrpc) serveStreams(st ServerTransport) {

	if st != nil {
		logger.Debugln("RemoteAddr : ", st.RemoteAddr().String())
		k2i.K2GrpcData(st.RemoteAddr().String())
	}
	s.serveStreams_s(st)
	k2i.K2RemoveGrpcData()
	return
}

//go:noinline
func (s *K2ServeStructGrpc) serveStreams_s(st ServerTransport) {
	if st != nil {
		logger.Debugln("RemoteAddr : ", st.RemoteAddr().String())
		k2i.K2GrpcData(st.RemoteAddr().String())
	}
	s.serveStreams_s(st)
	k2i.K2RemoveGrpcData()
	return
}

//go:noinline
func K2newClientStream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (_ grpc.ClientStream, err error) {
	logger.Debugln("------------K2newClientStream---------")
	url := ""
	var eventID = k2i.GetDummyEvent()
	if cc != nil {
		url = cc.Target()
		host, port, _ := net.SplitHostPort(url)
		logger.Debugln("url : ", url, " host : ", host, " port : ", port, " method: ", method)
		url = url + method
		proto := "http"
		if url != "" {
			url = proto + "://" + url
			logger.Debugln("final url ", url)
			var dummy map[string][]string
			eventID = k2i.K2request(url, host, port, true, dummy)
		}
	}
	if ctx != nil {
		if eventID != nil {
			key, value := k2i.GetTraceHeader(eventID)
			logger.Debugln("k2 tracing data : ", value)

			if key != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, key, value)
			}
		}
		value := k2i.GetApiCaller(url)
		ctx = metadata.AppendToOutgoingContext(ctx, "K2-API-CALLER", value)
		value = k2i.GetFuzzHeader()
		if value != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "k2-fuzz-request-id", value)
		}
	}
	out, e := K2newClientStream_s(ctx, desc, cc, method, opts...)
	k2i.SendExitEvent(eventID, e)
	return out, e

}

//go:noinline
func K2newClientStream_s(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (_ grpc.ClientStream, err error) {
	logger.Debugln("------------K2newClientStream---------")
	url := ""
	var eventID = k2i.GetDummyEvent()
	if cc != nil {
		url = cc.Target()
		host, port, _ := net.SplitHostPort(url)
		logger.Debugln("url : ", url, " host : ", host, " port : ", port, " method: ", method)
		url = url + method
		proto := "http"
		if url != "" {
			url = proto + "://" + url
			logger.Debugln("final url ", url)
			var dummy map[string][]string
			eventID = k2i.K2request(url, host, port, true, dummy)
		}
	}
	if ctx != nil {
		if eventID != nil {
			key, value := k2i.GetTraceHeader(eventID)
			logger.Debugln("k2 tracing data : ", value)

			if key != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, key, value)
			}
		}
		value := k2i.GetApiCaller(url)
		ctx = metadata.AppendToOutgoingContext(ctx, "K2-API-CALLER", value)
		value = k2i.GetFuzzHeader()
		if value != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "k2-fuzz-request-id", value)
		}
	}
	out, e := K2newClientStream_s(ctx, desc, cc, method, opts...)
	k2i.SendExitEvent(eventID, e)
	return out, e

}

func hook() {
	if k2i.DropHook_grpc() {
		return
	}
	_, e := k2i.HookWrapRawNamed("google.golang.org/grpc.(*Server).serveStreams", (*K2ServeStructGrpc).serveStreams, (*K2ServeStructGrpc).serveStreams_s)
	k2i.IsHookedLog("google.golang.org/grpc.(*Server).serveStreams", e)
	_, e = k2i.HookWrapRawNamed("google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders", (*K2Operateheader).Operateheader, (*K2Operateheader).Operateheader_s)
	k2i.IsHookedLog("(*http2Server).operateHeaders", e)
	_, e = k2i.HookWrapRawNamed("google.golang.org/grpc/internal/transport.(*http2Server).handleData", (*K2Parser).RecvMsg, (*K2Parser).RecvMsg_s)
	k2i.IsHookedLog("(*http2Server).handleData", e)
	_, e = k2i.HookWrapRawNamed("google.golang.org/grpc/encoding/proto.codec.Unmarshal", (K2codec).Unmarshal, (K2codec).Unmarshal_s)
	k2i.IsHookedLog("proto.codec.Unmarshal", e)
	e = k2i.HookWrapInterface((*grpc.Server).Serve, (*K2ServeStructGrpc).k2Server, (*K2ServeStructGrpc).k2Server_s)
	k2i.IsHookedLog("(*grpc.Server).Serve", e)
	_, e = k2i.HookWrapRawNamed("google.golang.org/grpc.invoke", K2Invoke, K2Invoke_s)
	k2i.IsHookedLog("google.golang.org/grpc.invoke", e)
	_, e = k2i.HookWrapRawNamed("google.golang.org/grpc.newClientStream", K2newClientStream, K2newClientStream_s)
	k2i.IsHookedLog("google.golang.org/grpc.newClientStream", e)
}

func initBlackOps() {
	k2secure_ws.FuzzGrpcClient = K2GrpcFuzz{}
}
func init() {

	if k2i.K2OK("k2secure_grpc") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	hook()
	initBlackOps()

}
