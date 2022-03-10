// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_grpcwrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	grpccurl "github.com/fullstorydev/grpcurl"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/jhump/protoreflect/desc"
	k2event "github.com/k2io/go-k2secure/v2/k2secure_event"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
	k2fuzz "github.com/k2io/go-k2secure/v2/k2secure_ws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var Grpccounter = true

var myclient *grpc.ClientConn
var mysclient *grpc.ClientConn

type K2GrpcFuzz struct {
}

type k2GrpcHandler struct {
	method            *desc.MethodDescriptor
	methodCount       int
	reqHeaders        metadata.MD
	reqHeadersCount   int
	reqMessages       []string
	reqMessagesCount  int
	respHeaders       metadata.MD
	respHeadersCount  int
	respMessages      []string
	respTrailers      metadata.MD
	respStatus        *status.Status
	respTrailersCount int
}

func (grpc K2GrpcFuzz) K2Fuzz(fTask *k2fuzz.FuzzTask) {
	controlCommand := fTask.CcStruct
	fuzzRequest := fTask.FStruct
	args_len := len(controlCommand.Arguments)
	logger.Debugln("number of args for cc11 : ", args_len)
	if args_len < 2 {
		logger.Infoln("Number of args for cc < 2, returning")
		return
	}

	currentCaseType := controlCommand.Arguments[1]
	logger.Debugln("case type is : ", currentCaseType)
	FID := fmt.Sprintf("%v", fuzzRequest.Headers["k2-fuzz-request-id"])
	if Grpccounter {
		checkAndCreateconfFile()
		if len(confImportFiles) == 0 || len(confImportPaths) == 0 {
			logger.Errorln("k2GrpcConf.json File is missing, Please add the k2GrpcConf.json in application dir : ", confFilePath)
			logger.Errorln("Grpc Blackops is not running...")
			k2event.SendFuzzFailEvent(FID)
			return
		}
		if confImportFiles[0] == "" || confImportPaths[0] == "" {
			logger.Errorln("Grpc Running with Default Config, Please update the k2GrpcConf.json in application dir : ", confFilePath)
			logger.Errorln("Grpc Blackops is not running...")
			k2event.SendFuzzFailEvent(FID)
			return
		}
		Grpccounter = false
	}
	var grpcBody []interface{}
	err := json.Unmarshal([]byte(fuzzRequest.Body), &grpcBody)
	if err != nil {
		logger.Errorln("error in Unmarshal Grpc Body : ", err.Error())
		k2event.SendFuzzFailEvent(FID)
		return
	}
	data := grpcBody
	var finalData []string
	for _, value := range data {
		jsonString, _ := json.Marshal(value)
		finalData = append(finalData, string(jsonString))
	}

	var headers []string
	for key, element := range fuzzRequest.Headers {
		if !strings.HasPrefix(key, ":") && key != "content-type" {
			tmp := fmt.Sprintf("%s: %s", key, element)
			headers = append(headers, tmp)
		}

	}
	gPort := strconv.Itoa(fuzzRequest.ServerPort)
	h := &k2GrpcHandler{reqMessages: finalData}
	error := rungrpc(fuzzRequest.Protocol, k2i.Info.ApplicationInfo.ServerIp+":"+gPort, fuzzRequest.Url, h, headers, fuzzRequest.ServerName)
	if error != nil {
		logger.Errorln("Failed fuzz req while doing : ", fuzzRequest.Url, fuzzRequest.Method, error.Error())
		k2event.SendFuzzFailEvent(FID)
	} else {
		logger.Infoln("Successfull fuzz req : ", fuzzRequest.Method, fuzzRequest.Url)
	}
	return
}

func rungrpc(proto string, client string, url string, h *k2GrpcHandler, headers []string, sni string) error {
	var grpc_client *grpc.ClientConn
	var err error
	if proto == "https" {
		if mysclient == nil {
			grpc_client, err = grpc.Dial(client, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, ServerName: sni})), grpc.WithBlock())
		} else {
			grpc_client = mysclient
		}
	} else {
		if mysclient == nil {
			grpc_client, err = grpc.Dial(client, grpc.WithInsecure(), grpc.WithBlock())
		} else {
			grpc_client = myclient
		}
	}
	if err != nil {
		return err
	}
	defer grpc_client.Close()
	refSource, err := grpccurl.DescriptorSourceFromProtoFiles(confImportPaths, confImportFiles...)
	if err != nil {
		return err
	}
	if len(url) > 1 && strings.HasPrefix(url, "/") {
		url = url[1:]
	}
	err = grpccurl.InvokeRpc(context.Background(), refSource, grpc_client, url, headers, h, h.getRequestData)
	logger.Errorln("rungrpc ERR : ", err)
	logger.Debugln("rungrpc Responce : ", h.respMessages)
	return err
}

func (h *k2GrpcHandler) getRequestData() ([]byte, error) {
	h.reqMessagesCount++
	if h.reqMessagesCount > len(h.reqMessages) {
		return nil, io.EOF
	}
	if h.reqMessagesCount > 1 {
		time.Sleep(time.Millisecond * 50)
	}
	return []byte(h.reqMessages[h.reqMessagesCount-1]), nil
}

func (h *k2GrpcHandler) OnResolveMethod(md *desc.MethodDescriptor) {
	h.methodCount++
	h.method = md
}

func (h *k2GrpcHandler) OnSendHeaders(md metadata.MD) {
	h.reqHeadersCount++
	h.reqHeaders = md
}

func (h *k2GrpcHandler) OnReceiveHeaders(md metadata.MD) {
	h.respHeadersCount++
	h.respHeaders = md
}

func (h *k2GrpcHandler) OnReceiveResponse(msg proto.Message) {
	//TODO
	jsm := jsonpb.Marshaler{Indent: "  "}
	respStr, err := jsm.MarshalToString(msg)
	if err != nil {
		panic(fmt.Errorf("failed to generate JSON form of response message: %v", err))
	}
	h.respMessages = append(h.respMessages, respStr)
}

func (h *k2GrpcHandler) OnReceiveTrailers(stat *status.Status, md metadata.MD) {
	h.respTrailersCount++
	h.respTrailers = md
	h.respStatus = stat
}
