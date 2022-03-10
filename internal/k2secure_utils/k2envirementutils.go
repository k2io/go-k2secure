// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_utils

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

/*
Constants for detect environment
*/
const (
	DOCKER_STR    = "docker/"
	ECS_DIR       = "ecs/"
	KUBEPODS_DIR  = "kubepods/"
	LXC_DIR       = "lxc/" // for older versions of docker
	DIR_SEPERATOR = "/"
	DOCKER_1_13   = "/docker-" //for docker 1.13.1 version
	SCOPE         = ".scope"
	CGROUP        = "/proc/self/cgroup"
	NAMESPACE     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// ---------------------------------------------------
// DevOps Environment utils
// ---------------------------------------------------

func IsKubernetes() bool {
	env := os.Getenv("KUBERNETES_SERVICE_HOST")
	return env != ""
}

func GetKubernetesNS() string {

	data, e := ioutil.ReadFile(NAMESPACE)
	if e != nil {
		return ""
	}
	return string(data)
}

func GetPodId() string {
	file, e := os.Open(CGROUP)
	if e != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := scanner.Text()
		counter := strings.LastIndex(text, KUBEPODS_DIR)
		if counter >= 0 {
			lines := strings.Split(text, "/")
			if len(lines) > 2 {
				id := lines[len(lines)-2]
				return id
			}
		}
		counter = strings.Index(text, "kubepods.slice/")
		if counter > -1 {
			counter1 := strings.Index(text, "kubepods-besteffort-pod")
			counter2 := strings.Index(text, "slice")
			if counter1 > -1 && counter2 > -1 {
				return text[counter1:counter2]
			}
		}

	}
	return ""
}

func GetContainerId() (bool, string, error) {
	file, e := os.Open(CGROUP)
	if e != nil {
		return false, "", errors.New("CGROUP file doesn't exist")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := scanner.Text()
		counter := strings.LastIndex(text, DOCKER_STR)
		if counter >= 0 {
			id := text[counter+len(DOCKER_STR):]
			return true, id, nil
		}
		counter = strings.LastIndex(text, ECS_DIR)
		if counter >= 0 {
			id := text[strings.LastIndex(text, DIR_SEPERATOR)+len(DIR_SEPERATOR):]
			return true, id, nil
		}
		counter = strings.LastIndex(text, KUBEPODS_DIR)
		if counter >= 0 {
			id := text[strings.LastIndex(text, DIR_SEPERATOR)+len(DIR_SEPERATOR):]
			return true, id, nil
		}
		counter = strings.LastIndex(text, LXC_DIR)
		if counter >= 0 {
			id := text[counter+len(LXC_DIR):]
			return true, id, nil
		}
		counter = strings.LastIndex(text, DOCKER_1_13)
		counter_end := strings.LastIndex(text, SCOPE)
		if counter >= 0 && counter_end >= 0 {
			id := text[counter+len(DOCKER_1_13) : counter_end]
			return true, id, nil
		}
	}
	file.Close()

	return false, "", nil
}

// ---------------------------------------------------
// Host Environment utils
// ---------------------------------------------------

func IcAgentEndPoint(runtime_environment string) string {
	host_ip := "127.0.0.1"
	if runtime_environment == "KUBERNETES" {
		host_ip = os.Getenv("K2_SERVICE_SERVICE_HOST")
	} else if runtime_environment == "CONTAINER" {
		host_ip = getDefaultGateway()
	} else if runtime_environment == "HOST" {
		host_ip = "127.0.0.1"
	}
	return host_ip
}

func getDefaultGateway() string {

	file, e := os.Open("/proc/self/net/route")
	if e != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := scanner.Text()
		lines := strings.Split(text, "\t")
		if len(lines) < 3 {
			return ""
		}
		if CaseInsensitiveEquals(lines[1], "00000000") {
			return getDefaultGatewayHex(lines[2])
		}
	}
	return ""
}

func getDefaultGatewayHex(hexGateway string) string {
	var gateway = ""
	for i := len(hexGateway) - 2; i >= 0; i -= 2 {
		var hex = hexGateway[i : i+2]
		str, _ := strconv.ParseUint(hex, 16, 64)
		tmp := fmt.Sprintf("%v", str)
		gateway = gateway + tmp
		gateway = gateway + "."
	}

	if string(gateway[len(gateway)-1]) == "." {
		gateway = gateway[0 : len(gateway)-1]
	}

	return gateway
}
func IntToString(input int) string {
	return strconv.Itoa(input)
}

func Int64ToString(input int64) string {
	return strconv.FormatInt(input, 10)
}
