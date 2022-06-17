// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_restclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
)

var restclient *http.Client
var cveclient *http.Client

func GetAgentPolicy(groupName, k2resource, appUUID, apiAccessorToken, customerId string) (appPolicy k2models.WebAppPolicy, responce string, err error) {
	if restclient == nil {
		restclient = &http.Client{Timeout: 0}
	}
	var request *http.Request
	var response *http.Response
	request, err = http.NewRequest(http.MethodGet, k2resource+"/collector/policy", nil)
	query := request.URL.Query()
	query.Set("group", groupName)
	query.Set("applicationUUID", appUUID)
	request.URL.RawQuery = query.Encode()

	request.Header.Set("K2_API_ACCESSOR_TOKEN", apiAccessorToken)
	request.Header.Set("K2_CUSTOMER_ID", customerId)

	response, err = restclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	responce = string(bodyBytes)
	if err != nil {
		return
	}
	if response.StatusCode == 200 {
		err = json.Unmarshal(bodyBytes, &appPolicy)
		return
	} else {
		return appPolicy, responce, errors.New("invalid response " + responce)
	}
}

func PostAgentPolicy(groupName, k2resource, appUUID, apiAccessorToken, customerId, body string) (err error) {
	if restclient == nil {
		restclient = &http.Client{Timeout: 0}
	}
	var request *http.Request
	var response *http.Response
	request, err = http.NewRequest(http.MethodPost, k2resource+"/collector/policy/update", strings.NewReader(body))
	query := request.URL.Query()
	query.Set("group", groupName)
	query.Set("applicationUUID", appUUID)
	request.URL.RawQuery = query.Encode()

	request.Header.Set("K2_API_ACCESSOR_TOKEN", apiAccessorToken)
	request.Header.Set("K2_CUSTOMER_ID", customerId)
	request.Header.Set("Content-Type", "application/json")
	response, err = restclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		err = nil
	} else {
		err = fmt.Errorf("Error during PostAgentPolicy", response)
	}
	return
}

func GetCVEVersion(platform, arch, k2resource, apiAccessorToken, customerId string) (data k2models.CveScanVersion, err error) {
	if platform == "darwin" {
		platform = "mac"
	}
	if cveclient == nil {
		cveclient = &http.Client{Timeout: 0}
	}
	var request *http.Request
	var response *http.Response
	request, err = http.NewRequest(http.MethodGet, k2resource+"/collector/cve/version", nil)
	query := request.URL.Query()
	query.Set("platform", platform)
	query.Set("arch", arch)
	request.URL.RawQuery = query.Encode()

	request.Header.Set("K2_API_ACCESSOR_TOKEN", apiAccessorToken)
	request.Header.Set("K2_CUSTOMER_ID", customerId)
	response, err = cveclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode == 200 {
		err = json.Unmarshal(bodyBytes, &data)
		return data, nil

	}
	return

}

func GetCVETar(path, platform, arch, k2resource, apiAccessorToken, customerId, version, appUUID, requiredCollectorHash string) (fileName string, err error) {
	if platform == "darwin" {
		platform = "mac"
	}

	if cveclient == nil {
		cveclient = &http.Client{Timeout: 0}
	}
	var request *http.Request
	var response *http.Response
	//	var requiredCollectorHash string
	request, err = http.NewRequest(http.MethodGet, k2resource+"/collector/cve", nil)
	if err != nil {
		return
	}
	query := request.URL.Query()
	query.Set("platform", platform)
	query.Set("arch", arch)
	query.Set("version", version)
	request.URL.RawQuery = query.Encode()

	request.Header.Set("K2_API_ACCESSOR_TOKEN", apiAccessorToken)
	request.Header.Set("K2_CUSTOMER_ID", customerId)

	response, err = cveclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		var mediaType string
		var params map[string]string
		mediaType, params, err = mime.ParseMediaType(response.Header.Get("Content-Disposition"))
		if err != nil {
			return
		}
		var ok bool
		fileName, ok = params["filename"]
		if !ok || mediaType != "attachment" {
			err = fmt.Errorf("no filename provided in response :: %s :: Status : %d :: Content-Disposition : %s", request.URL.String(), response.StatusCode, response.Header.Get("Content-Disposition"))
			return
		}
		cvetarSavePath := filepath.Join(path, fileName)
		// var oldCollectorHash string
		_, err = os.Stat(cvetarSavePath)

		err = os.MkdirAll(filepath.Dir(cvetarSavePath), os.ModePerm)
		if err != nil {
			err = fmt.Errorf("unable to create cve scan save directory :: %s :: Status : %d :: Content-Disposition : %s :: %v", request.URL.String(), response.StatusCode, response.Header.Get("Content-Disposition"), err)
			return
		}
		var outFile *os.File
		outFile, err = os.Create(cvetarSavePath)
		if err != nil {
			return "", fmt.Errorf("unable to create cve scan tar file :: %s :: Status : %d :: Content-Disposition : %s :: %v", request.URL.String(), response.StatusCode, response.Header.Get("Content-Disposition"), err)
		}
		defer outFile.Close()
		defer outFile.Sync()
		_, err = io.CopyBuffer(outFile, response.Body, make([]byte, 4*1024))
		if err != nil {
			return "", fmt.Errorf("unable to save cve scan tar :: %s :: Status : %d :: Content-Disposition : %s :: %v", request.URL.String(), response.StatusCode, response.Header.Get("Content-Disposition"), err)
		}
		var observedCollectorHash string
		observedCollectorHash = k2utils.CalculateSha256(cvetarSavePath)
		if err != nil {
			os.Remove(cvetarSavePath)
			return
		}
		if observedCollectorHash != requiredCollectorHash {
			err = errors.New(fmt.Sprintf(" cve scan tar hash mismatch. got : %s. required : %s", observedCollectorHash, requiredCollectorHash))
			//logger.WithError(err).WithField("collectorName", collectorName).Errorln("Downloaded collector hash mismatch")
			os.Remove(cvetarSavePath)
			return
		}

		// logger.WithField("bytesWritten", n).WithField("collectorFile", collectorSavePath).WithField("collectorName", collectorName).Infoln("Collector fetched successfully")
		return
	} else {
		bodyBytes, errRead := ioutil.ReadAll(response.Body)
		defer response.Body.Close()
		if errRead != nil {
			//	logger.Errorln(fmt.Sprintf("call to API GetCollector failed :: %s :: Status : %d", request.URL.String(), response.StatusCode))
			return
		}
		err = fmt.Errorf("call to API Get cve scan tar failed :: %s :: Status : %d :: Response : %s", request.URL.String(), response.StatusCode, string(bodyBytes))
	}
	return
}

func UploadLogs(logFilePath, apiAccessorToken, customerId, appUUID, k2resource string) (err error) {

	pReader, pWriter := io.Pipe()
	defer pReader.Close()

	writer := multipart.NewWriter(pWriter)

	go func() {
		defer pWriter.Close()
		defer writer.Close()
		err = writer.WriteField("applicationUUID", appUUID)
		if err != nil {
			return
		}

		err = writer.WriteField("customerId", customerId)
		if err != nil {
			return
		}
		err = writer.WriteField("saveName", filepath.Base(logFilePath))
		if err != nil {
			return
		}
		var part io.Writer
		part, err = writer.CreateFormFile("file", filepath.Base(logFilePath))
		if err != nil {
			return
		}
		var fileToUpload *os.File
		fileToUpload, err = os.Open(logFilePath)
		if err != nil {
			return
		}
		defer fileToUpload.Close()

		if _, err = io.CopyBuffer(part, fileToUpload, make([]byte, 4*1024)); err != nil {
			return
		}

	}()
	var request *http.Request
	var response *http.Response
	request, err = http.NewRequest(http.MethodPost, k2resource+"/collector/uploadLog", pReader)
	if err != nil {
		return
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("K2_API_ACCESSOR_TOKEN", apiAccessorToken)
	request.Header.Set("K2_CUSTOMER_ID", customerId)

	cveclient := &http.Client{Timeout: 0}
	response, err = cveclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}

	bodyString := string(bodyBytes)
	if response.StatusCode != 201 {
		err = fmt.Errorf("call to IC API UploadLogs failed :: %s :: Status : %d :: Response : %s", request.URL.String(), response.StatusCode, bodyString)

	}
	return
}

func GetGlobalPolicy(k2resource, apiAccessorToken, customerId, currentVersion string) (appPolicy k2models.GlobalPolicy, responce string, err error) {
	if restclient == nil {
		restclient = &http.Client{Timeout: 0}
	}
	if currentVersion == "" {
		currentVersion = "0"
	}
	var request *http.Request
	var response *http.Response
	request, err = http.NewRequest(http.MethodGet, k2resource+"/collector/policy/parameter", nil)
	query := request.URL.Query()
	query.Set("currentVersion", currentVersion)

	request.URL.RawQuery = query.Encode()
	request.Header.Set("K2_API_ACCESSOR_TOKEN", apiAccessorToken)
	request.Header.Set("K2_CUSTOMER_ID", customerId)
	response, err = restclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	responce = string(bodyBytes)
	if err != nil {
		return
	}
	if response.StatusCode == 200 {
		err = json.Unmarshal(bodyBytes, &appPolicy)
		return
	} else {
		return appPolicy, responce, errors.New("invalid response " + responce)
	}

}
