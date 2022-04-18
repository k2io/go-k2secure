// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ws

import (
	"encoding/json"
	"errors"
	"strings"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
	k2policy "github.com/k2io/go-k2secure/v2/k2secure_policy"
)

var unmarshalledBuf []byte
var maxUnmarshalled = 4096 * 4

func ParseControlCode(argbuf []byte) error {

	var kcc k2models.K2ControlComand
	buf := argbuf
	err := json.Unmarshal(buf, &kcc)

	if err != nil {
		// use prior buffer to unmarshal
		xb := append(unmarshalledBuf, buf...)
		err := json.Unmarshal(xb, &kcc)
		if err != nil { //k2
			logger.Errorln("error while unmarshalling json : ", string(buf))
			unmarshalledBuf = xb
			if len(xb) > maxUnmarshalled {
				unmarshalledBuf = make([]byte, 0) //empty
				logger.Errorln("CC() - Reset buf, unable to unmarshall JSON : ", string(xb))
			} else {
				logger.Errorln("CC() - Retain buf, unable to unmarshall JSON : ", string(xb))
			}
			return err
		} else {
			logger.Infoln("CC() - Reset buf, ok JSON:", string(xb))
			unmarshalledBuf = make([]byte, 0) //empty
		}
		buf = xb
	}
	cc := kcc.ControlCommand
	logger.Debugln("Control command : ", cc)

	switch cc {
	case 4:
		// logger.Infoln("CC(4) - UploadLogs")
		// isSuccess := UploadLog(logging.LogfileAbsPath)
		// if isSuccess {
		// 	logger.Infoln("Log file upload successful")
		// } else {
		// 	logger.Errorln("Failed to upload the log file")
		// }
	case 10:
		logging.NewStage("6", "POLICY", "Received policy data from Prevent-Web service")
		k2policy.SendPolicyFetchRequest()
		logging.EndStage("6", "POLICY")
		err := k2policy.Initialise()
		if err != nil {
			logger.Errorln(err)
		}
	case 11:
		//todo

		if fuzzThreadPool == nil {
			initFuzzThreadPool()
		}
		if len(kcc.Arguments) <= 0 {
			break
		}
		stringArg := strings.Replace(kcc.Arguments[0], "{{K2_HOME_TMP}}", k2i.CVE_TAR_SPACE, -1)
		stringArg = strings.Replace(stringArg, "%7B%7BK2_HOME_TMP%7D%7D", k2i.CVE_TAR_SPACE, -1)
		arg := []byte(stringArg)
		var kcc11 k2models.Fuzz_struct
		err = json.Unmarshal(arg, &kcc11)
		if err != nil {
			return errors.New("Unable to unmarshall cc11 : " + err.Error())
		} else {
			logger.Debugln("will fuzz, parsedOK ..")
			// go fuzz(kcc11)
			submitFuzzTask(kcc, kcc11)
			break //ignore the rest
		}

	case 101:
		var blocking k2models.K2ControlCode101_struct
		err := json.Unmarshal(buf, &blocking)
		if err != nil {
			logger.Errorln("Unable to unmarshall cc101 ", err)
		} else {
			logger.Debugln("blocking data", blocking.Data)
		}
	}

	return nil
}

func init() {
	unmarshalledBuf = make([]byte, 0)
}
