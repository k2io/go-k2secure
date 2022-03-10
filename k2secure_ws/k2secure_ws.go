// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ws

import (
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2rest "github.com/k2io/go-k2secure/v2/internal/k2secure_restclient"
	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	"github.com/k2io/go-k2secure/v2/k2secure_event"

	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var logger = logging.GetLogger("wsclient")
var reconnect = true

const validatorDefaultEndpoint = "ws://localhost:54321/"

// -----------------------------------------------------------
// websockets
// -----------------------------------------------------------
type k2ws struct {
	Conn *websocket.Conn
}

var Wslock sync.Mutex
var StartMsgPendingFlag bool

func MarkStartMsgPending(x bool) {
	Wslock.Lock()
	StartMsgPendingFlag = x
	Wslock.Unlock()
}
func StartMsgPending() bool {
	res := false
	Wslock.Lock()
	res = (StartMsgPendingFlag == true)
	Wslock.Unlock()
	return res
}

// -----------------------------------------------------------
// Func RawConnReset - raw connection reset - set Conn nil
// -----------------------------------------------------------
func (k *k2ws) RawConnReset(m string) {
	logger.Debugln("RawConnReset : caller : ", m, k2i.K2getID())
	Wslock.Lock()
	if k.Conn != nil {
		k.Conn.Close()
	}
	k.Conn = nil
	if k.Conn == nil {
		logger.Debugln("k.Conn is nil after reset")
	} else {
		logger.Debugln("k.Conn is not nil after reset")
	}
	k2i.Info.AgentInfo.SecureWSready = false
	Wslock.Unlock()
}

// -----------------------------------------------------------
// Func RawConnOK - check if Conn is nil
// -----------------------------------------------------------
func (k *k2ws) RawConnOK(isFromLoop bool) bool {
	res := false
	Wslock.Lock()
	res = (k.Conn != nil)
	Wslock.Unlock()
	if !isFromLoop {
		logger.Debugln("RawConnOK : ", res)
	}
	return res
}

// -----------------------------------------------------------
// Function: k2ws.Send - buffer for sending.
// -----------------------------------------------------------
func (k *k2ws) Send(s []byte) int {
	k2i.Info.EventData.EventProcessCount++
	if k2i.Info.EventData.EventProcessCount == 0 {
		k2i.Info.EventData.EventProcessCount = math.MaxUint64
	}
	k2i.K2SetUnflushed(cringCount() + 1)
	r := cringAdd(s)
	logger.Debugln("added to cring : " + strconv.FormatInt(int64(r), 10))

	if r < 0 { //cring full
		logger.Errorln("cring.Full : Unable to add event to cring : " + string(s))
		k2i.Info.EventData.DropEventCount++
		if k2i.Info.EventData.DropEventCount == 0 {
			k2i.Info.EventData.DropEventCount = math.MaxUint64
		}
		return r
	}
	return len(s)
}

// -----------------------------------------------------------
// Function: k2ws.RawConnect - connect if not connected.
// -----------------------------------------------------------
func (k *k2ws) RawConnect() int {
	ok := k.RawConnOK(false)
	if !ok {
		logger.Warningln("RawConnnect : connection NOT ok")
		res := k.Reconnect()
		if !res {
			logger.Errorln("RawConnnect : k.Reconnect return err -1")
			return -1
		}
	}
	return 0
}

// -----------------------------------------------------------
// Function: k2ws.RawSend - send from buffer
// -----------------------------------------------------------
func (k *k2ws) RawSend(s []byte) int {
	if debug_drop_send {
		return -1
	}
	r := k.RawConnect()
	if r < 0 {
		return r
	}
	Wslock.Lock()
	e := (k).Conn.WriteMessage(websocket.TextMessage, s)
	Wslock.Unlock()
	strS := string(s)
	sentLen := len(s)
	if e != nil {
		logger.Errorln("K2secure message send failed : "+strS, e.Error())
		k2i.Info.EventData.DropEventCount++
		if k2i.Info.EventData.DropEventCount == 0 {
			k2i.Info.EventData.DropEventCount = math.MaxUint64
		}
		k.RawConnReset("RawSend Connect ERR : " + e.Error()) //reset so we reconnect
		return -1
	}
	k2i.Info.EventData.EventCount++
	if k2i.Info.EventData.EventCount == 0 {
		k2i.Info.EventData.EventCount = math.MaxUint64
	}
	logger.Debugln("K2secure - message sent: " + strconv.FormatInt(int64(sentLen), 10))
	MarkStartMsgPending(false)
	return sentLen
}

// -----------------------------------------------------------
// Function: k2ws.PendingSend
// -----------------------------------------------------------
func (k *k2ws) PendingSend() {
	if cringEmptyUnlocked() {
		k2i.K2ResetUnflushed()
		return
	}
	s := cringPeek()
	r := k.RawSend(s)
	if r < 0 {
	} else {
		cringRemove()
	}
}

// -----------------------------------------------------------
// Function: k2ws.Read
// -----------------------------------------------------------
func (k *k2ws) Read() (int, []byte, error) {

	r := k.RawConnect()
	if r < 0 {
		return r, nil, nil
	}
	if k.Conn != nil {
		_, message, err := (k.Conn).ReadMessage()
		if err != nil && (err != io.EOF) {
			logger.Errorln("Read error ERR : ", err.Error())
		}
		return len(string(message)), message, err
	}
	return -1, nil, errors.New("Read : Conn is nil")
}

// -----------------------------------------------------------
// Function: connect/reconnect Websocket
// -----------------------------------------------------------
func (k *k2ws) Reconnect() bool {
	if k.Conn != nil {
		logging.PrintInitlog("Websocket connection already initialized : Skip", "WS")
		k2secure_event.SendApplicationInfo() // sending updated appinfo
	}
	if reconnect {
		Wslock.Lock()
		validatorEndpoint := ""
		if len(k2i.Info.AgentInfo.K2validator) == 0 {
			validatorEndpoint = validatorDefaultEndpoint
		} else {
			validatorEndpoint = k2i.Info.AgentInfo.K2validator
		}
		headers := http.Header{
			"K2-CONNECTION-TYPE":  []string{"LANGUAGE_COLLECTOR"},
			"K2-API-ACCESSOR":     []string{k2i.Info.CustomerInfo.ApiAccessorToken},
			"K2-CUSTOMER-ID":      []string{strconv.Itoa(k2i.Info.CustomerInfo.CustomerId)},
			"K2-VERSION":          []string{k2utils.CollectorVersion},
			"K2-COLLECTOR-TYPE":   []string{k2utils.CollectorType},
			"K2-GROUP":            []string{k2i.Info.EnvironmentInfo.GroupName},
			"K2-APPLICATION-UUID": []string{k2i.Info.ApplicationInfo.AppUUID},
			"K2-BUILD-NUMBER":     []string{k2utils.BuildNumber},
			"K2-JSON-VERSION":     []string{k2utils.JsonVersion},
		}
		logging.PrintInitlog("Connecting to Prevent-Web service at : "+validatorEndpoint, "WS")
		conn, _, e := websocket.DefaultDialer.Dial(validatorEndpoint, headers)
		if e != nil {
			logging.PrintInitErrolog("Error connecting to Prevent-Web service at : "+e.Error(), "WS")
			logger.Errorln("error reconnecting... : "+e.Error(), validatorEndpoint)
			k.Conn = nil
		} else if conn == nil {
			logging.PrintInitErrolog("Error connecting to Prevent-Web service at : "+validatorEndpoint, "WS")
			logger.Errorln("K.Reconnect init k.Conn nil, noERR... : ", validatorEndpoint)
			k.Conn = nil
		} else {
			logging.PrintInitlog("Connected to Prevent-Web service at : "+validatorEndpoint, "WS")
			logger.Infoln("K.Reconnect init k.Conn successful", validatorEndpoint)
			k.Conn = conn
			// k.Conn.MaxPayloadBytes = 0 //default MAX
			if !k2i.Info.AgentInfo.SecureWSready {
				k2secure_event.InitWS(k)
				if !debug_ws_thread_off {
					logger.Infoln("!!! Websocket worker goroutine starting...")
					go k2wsthread(k, true)
					//go k2wsthread(k,false)
				}
				logging.EndStage("4", "WS")
			}
		}
		res := k.Conn != nil
		Wslock.Unlock()
		if res {
			if !StartMsgPending() {
				logger.Infoln("K.Reconnect now SendStartEvent ...")
				MarkStartMsgPending(true)
				k2secure_event.SendApplicationInfo()
			}
			logger.Infoln("K.(Re)connect done ...")
		}
		return res
	} else {
		logger.Errorln("Websocket init failed", "WS")
		return false
	}

}

var waitTime = 1

func K2WebSocketRetry(k *k2ws) bool {
	logger.Infoln("Try to reconnect with IC agent time =", waitTime)
	if waitTime > 6 {
		waitTime = 0
		logger.Infoln("Not able to Connect IC after 30 min")
		return true
	} else {
		sleeptimeForReconnect := time.Duration(waitTime) * time.Minute
		time.Sleep(sleeptimeForReconnect)
		conected := k.RawConnOK(false)
		if !conected {
			response := k.Reconnect()
			if !response {
				logger.Infoln("Not able to connect IC agent wait time : ", waitTime)
				waitTime++
				return false
			} else {
				waitTime = 1
				logger.Infoln("IC agent reconnection done")
				return false
			}
		} else {
			waitTime = 1
			logger.Infoln("IC agent reconnection already done")
			return true
		}
	}

}

func k2ReadThread(k *k2ws) {
	for {
		n, buf, err := k.Read()
		if n > 0 {
			logger.Debugln("Buff received : ", string(buf))
			errP := ParseControlCode(buf)
			if errP != nil {
				logger.Errorln("k2wsthread : received JSON-unparsed msg : ", errP.Error(), " : ", string(buf))
			} else {
				logger.Debugln("k2wsthread : received control msg : ", strconv.FormatInt(int64(n), 10), " : ", string(buf))
			}
		} else {
			logger.Errorln("value of read is less than 0")
		}
		if err != nil {
			logger.Errorln("Error received while reading : " + err.Error())
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
				logger.Errorln("error unexpected close : ", err)
				k.RawConnReset("k2ReadThread Connect ERR : " + err.Error()) //reset so we reconnect
				return
			}
		}
	}
}

// -----------------------------------------------------------
// Thread1 - wait receive - control commands from server.
// Thread2 - pending send and healthcheck
// -----------------------------------------------------------

func k2wsthread(k *k2ws, sender bool) {
	sleeptime := 500 * time.Millisecond
	logger.Infoln("raw ws connection ", sender)
	go k2ReadThread(k)
	for {
		ok := k.RawConnOK(true)
		if !ok {
			break
		}
		for i := 0; i < 700; i++ { //25 events per each run
			k.PendingSend()
		}
		time.Sleep(sleeptime)
	}

	sleeptimeForReconnect := 5 * time.Minute
	for {
		ok := k.RawConnOK(false)
		if !ok {
			r := k.RawConnect()
			if r < 0 {
				logger.Infoln("sleeping for sleeptimeForReconnect before reconnecting")
				time.Sleep(sleeptimeForReconnect)
				logger.Infoln("sleep ended, retrying to connect")
			} else {
				logger.Infoln("returning from k2wsthread from inside")
				return
			}
		} else {
			logger.Infoln("returning from k2wsthread from outside")
			return
		}
	}
}

func (k *k2ws) UploadLogOnRotationWS() {
	if !debug_ftp_log_upload_off {
		uploadLogOnRotation()
	}

}

var backupFileRegex = regexp.MustCompile(`(?i)\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}`)

func uploadLogOnRotation() {
	errX := filepath.Walk(k2i.LOG_FILE_PATH, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		} else {
			retVal := backupFileRegex.Find([]byte(path))
			if retVal != nil {
				isSuccess := k2rest.UploadLogs(path, k2i.Info.CustomerInfo.ApiAccessorToken, strconv.Itoa(k2i.Info.CustomerInfo.CustomerId), k2i.Info.ApplicationInfo.AppUUID, k2i.Info.AgentInfo.K2resource)
				if isSuccess == nil {
					logger.Debugln("uploadLogOnRotation Success")
					os.Remove(path)
				} else {
					logger.Errorln("error occurred while upload log dir : " + isSuccess.Error())
				}
			}
		}
		return nil
	})
	if errX != nil {
		logger.Errorln("error occurred while traversing log dir : " + errX.Error())
	}
	return
}

func K2Init(server_name string) {
	logging.NewStage("4", "WS", "Websocket connection")
	logger.Infoln("Server name : " + server_name)
	k2socket := new(k2ws)
	if !cringinit {
		cringInit()
	}
	if debug_ws_off {
		return
	}
	k2i.Info.ApplicationInfo.ServerName = append(k2i.Info.ApplicationInfo.ServerName, server_name)
	status := (k2socket).Reconnect()
	if !status {
		for {
			connected := K2WebSocketRetry(k2socket)
			logger.Infoln("connected status : ", connected)
			if connected {
				break
			}
		}
	}
}
