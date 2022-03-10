// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2event "github.com/k2io/go-k2secure/v2/k2secure_event"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
	k2fuzz "github.com/k2io/go-k2secure/v2/k2secure_ws"
)

// Copyright (C) 2021 K2 Cyber Security Inc.

var mytr *http.Transport
var myclient *http.Client
var mysclient *http.Client

type K2HttpFuzz struct {
}

func (grpc K2HttpFuzz) K2Fuzz(fTask *k2fuzz.FuzzTask) {
	cc := fTask.CcStruct
	f := fTask.FStruct
	args_len := len(cc.Arguments)
	logger.Debugln("number of args for cc11 : ", args_len)
	if args_len < 2 {
		logger.Infoln("Number of args for cc < 2, returning")
		return
	}
	currentCaseType := cc.Arguments[1]
	logger.Debugln("case type is : ", currentCaseType)
	FID := fmt.Sprintf("%v", f.Headers["k2-fuzz-request-id"])
	logger.Debugln("Fuzz func called")
	port := ""
	if len(f.ClientPort) > 0 {
		port = ":" + strconv.Itoa(f.ServerPort) // TODO change this
	}
	fuzzUrl := ""
	var client *http.Client

	if myclient == nil {
		myclient = &http.Client{Timeout: time.Second * 10}
	}
	if mytr == nil {
		if f.ServerName == "" {
			mytr = &http.Transport{
				Dial:                (&net.Dialer{Timeout: 5 * time.Second}).Dial,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				TLSHandshakeTimeout: 6 * time.Second,
				MaxIdleConns:        10,
				DisableCompression:  true}
		} else {
			mytr = &http.Transport{
				Dial:                (&net.Dialer{Timeout: 5 * time.Second}).Dial,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: f.ServerName},
				TLSHandshakeTimeout: 6 * time.Second,
				MaxIdleConns:        10,
				DisableCompression:  true}
		}
	}
	if mysclient == nil {
		mysclient = &http.Client{
			Timeout:   time.Second * 10,
			Transport: mytr}
	}
	if f.Protocol == "https" {
		fuzzUrl = "https://" + k2i.Info.ApplicationInfo.ServerIp + port + f.Url
		client = mysclient
	} else {
		fuzzUrl = "http://" + k2i.Info.ApplicationInfo.ServerIp + port + f.Url
		client = myclient
	}

	A := fmt.Sprintf("%v", f.Headers["Accept"])
	UA := fmt.Sprintf("%v", f.Headers["User-Agent"])

	logger.Debugln("Fuzz: headers adding ...", A, UA, FID)
	var req *http.Request = nil
	var err error = nil

	if f.Method == "GET" {
		req, err = http.NewRequest("GET", fuzzUrl, nil)
	} else if f.Method == "POST" {
		req, err = http.NewRequest("POST", fuzzUrl, strings.NewReader(f.Body))
	} else if f.Method == "POSTFORM" { // no need to handle
		logger.Debugln("TODO : Unimplemented : Fuzz POSTFORM")
	} else if k2utils.CaseInsensitiveEquals(f.Method, "grpc") {
		logger.Debugln("TODO : Unimplemented : Fuzz GRPC")
	} else {
		logger.Debugln("TODO : Unimplemented : Fuzz ", f.Method)
	}
	req.URL.RawQuery = req.URL.Query().Encode()
	// now handle the req and err
	if err != nil {
		logger.Errorln("Failed fuzz req while creating : ", f.Method, fuzzUrl, err.Error())
		// send fuzz fail event
		k2event.SendFuzzFailEvent(FID)
	} else if req != nil {
		for k, v := range f.Headers {
			sv := fmt.Sprintf("%v", v)
			if k2utils.CaseInsensitiveEquals(k, "Content-Length") {
				logger.Debugln("Skipping - k : ", k, " --v : ", sv)
			} else {
				req.Header.Add(k, sv)
				logger.Debugln("Adding - k : ", k, " --v : ", sv)
			}
		}
		req.Header.Add("Content-Type", f.ContentType)

		if client == nil {
			logger.Debugln("Blackops client = nil")
		}
		resp, err2 := client.Do(req)
		if resp != nil {
			io.Copy(os.Stdout, resp.Body)
			defer resp.Body.Close()
		}

		if err2 != nil {
			logger.Errorln("Failed fuzz req while doing : ", f.Method, fuzzUrl, err2.Error())
			k2event.SendFuzzFailEvent(FID)
			// send fuzz fail event
		} else {
			logger.Infoln("Successfull fuzz req : ", f.Method, fuzzUrl)
		}
	} else {
		logger.Errorln("Neither request was done no error fuzz req : ", f.Method, fuzzUrl)
	}
	return // check whether this return needed or not
}
