// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_impl

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"sync"

	k2model "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	k2Utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var hmutex sync.Mutex
var httpConnMap = sync.Map{}
var httpConnCacheMap = sync.Map{}

func reset(doreset bool) {
	if doreset {
		httpConnCacheMap = sync.Map{}
	} else {
		httpConnMap = sync.Map{}
	}
}

func getHttpConnMap(doreset bool) sync.Map {
	if doreset {
		return httpConnCacheMap
	} else {
		return httpConnMap
	}
}

func UpdateHttpConnsIn(r *k2model.Info_req) {
	serverPort := 8080
	if len(k2i.Info.ApplicationInfo.Ports) > 0 {
		serverPort = k2i.Info.ApplicationInfo.Ports[0]
	}
	header := r.HeaderMap
	data := ""
	for k, v := range header {
		if k2Utils.CaseInsensitiveEquals(k, "K2-API-CALLER") {
			data = v
		}
	}
	UpdateHttpConns(r.Url, "*", k2i.Info.ApplicationInfo.ServerIp, strconv.Itoa(serverPort), "INBOUND", data)
}

func UpdateHttpConnsOut(dest, dport, urlx string) {
	UpdateHttpConns(urlx, "0.0.0.0", dest, dport, "OUTBOUND", "")
}

func UpdateHttpConns(url, sourceIP, destinationIP, destinationPort, direction, sourceID string) {
	key := sourceIP + "," + destinationIP + "," + destinationPort + "," + cannonicalURL(url) + "," + sourceID
	hmutex.Lock()

	tmpCache, isPresentCache := httpConnCacheMap.Load(key)
	tmp, isPresent := httpConnMap.Load(key)

	if isPresent {
		tmp_info := tmp.(*k2models.HTTPConnections)
		tmp_info.Count++
	} else if isPresentCache {
		tmp_info := tmpCache.(*k2models.HTTPConnections)
		tmp_info.Count++
	} else {
		tmp_info := new(k2models.HTTPConnections)
		if direction == "INBOUND" && sourceID != "" {
			data := strings.Split(sourceID, "||")
			if len(data) == 4 {
				tmpSource := new(k2models.SourceID)
				tmpSource.ApplicationUUID = data[0]
				tmpSource.ContextPath = data[1]
				tmpSource.ServerPort = data[2]
				durl, error := base64.StdEncoding.DecodeString(data[3])
				if error == nil {
					tmpSource.Target = cannonicalURL(string(durl))
				}
				tmp_info.SourceID = tmpSource
			}
		}
		tmp_info.URL = cannonicalURL(url)
		tmp_info.SourceIP = sourceIP
		tmp_info.DestinationIP = destinationIP
		number, _ := strconv.ParseUint(destinationPort, 10, 32)
		tmp_info.DestinationPort = number
		tmp_info.Direction = direction
		tmp_info.Count = 1
		httpConnMap.Store(key, tmp_info)
		httpConnCacheMap.Store(key, tmp_info)

	}
	hmutex.Unlock()
	return
}

// ---------------------------------------------------------------------
// Func GetHttpConnectionsJSON - called from HealthCheck to send stats
// ---------------------------------------------------------------------
func GetHttpConnectionsJSON(isCached bool) []k2models.HTTPConnections {
	hmutex.Lock()
	resultMap := getHttpConnMap(isCached)
	var arg []k2models.HTTPConnections
	resultMap.Range(func(key interface{}, value interface{}) bool {
		arg = append(arg, *value.(*k2models.HTTPConnections))
		return true
	})
	reset(isCached)
	hmutex.Unlock()
	return arg

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
