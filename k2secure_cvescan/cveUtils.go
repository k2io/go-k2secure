// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_cvescan

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var (
	appScanYml   = ""
	envScanYml   = ""
	yml_tamplate = "#path to dependency check tool.\r\ndependencycheck.command: %s --enableExperimental \r\n# connecting back to k2agent.\r\nk2customer.customerId: %s\r\nk2customer.apiAccessorToken: %s\r\nk2agent.groupName: %s\r\nk2agent.websocket: %s\r\nk2agent.nodeId: %s\r\nk2agent.identifier.kind: %s\r\nk2agent.identifier.id: %s\r\n#----- following are file scan specific options\\r\nk2agent.scan.mode: file\r\nk2agent.application: %s\r\nk2agent.applicationUuid: %s\r\nk2agent.applicationSha256: %s\r\nk2agent.scanPath: %s\r\nk2agent.isEnv: %s\r\nk2agent.outputDir: %s\r\n"
	cveScanMutex sync.Mutex
	outputDir    = ""
)

// Initialization for CVE SCAN on CC 8

func RunCveScan(isApp, isEnv bool) {
	appScanYml = filepath.Join(k2i.CVE_TAR_SPACE, "K2", "service-input.yml")
	envScanYml = filepath.Join(k2i.CVE_TAR_SPACE, "K2", "envservice-input.yml")
	outputDir = filepath.Join(k2i.CVE_TAR_SPACE, "K2")
	cveScanMutex.Lock()
	if isApp {
		err := createServiceYml(false)
		if err != nil {
			logger.Errorln(err)
		} else {
			runCommand(appScanYml)
		}
	}
	if isEnv {
		err := createServiceYml(true)
		if err != nil {
			logger.Errorln(err)
		} else {
			runCommand(envScanYml)
		}
	}
	if os.Getenv("K2_CLEANUP") != "false" {
		deleteFile()
	}
	cveScanMutex.Unlock()
}

func createServiceYml(isEnv bool) (err error) {

	applicationName := filepath.Base(k2i.Info.ApplicationInfo.Cmd)
	if applicationName == "" {
		return errors.New("error in application scan : applicationName is nil")
	}

	var filename string
	var sha string
	var env string
	var path string
	if isEnv {
		filename = envScanYml
		sha = getEnvScanSha(k2i.Info.EnvironmentInfo.Gopath)
		env = "true"
		path = k2i.Info.EnvironmentInfo.Gopath
	} else {
		filename = appScanYml
		sha = k2i.Info.ApplicationInfo.Sha256
		env = "false"
		path = k2i.Info.EnvironmentInfo.Wd
	}
	filepath.Base(k2i.Info.ApplicationInfo.Cmd)
	str := fmt.Sprintf(yml_tamplate, k2i.DEPENDENCY_CHECK_COMMAD, k2utils.IntToString(k2i.Info.CustomerInfo.CustomerId), k2i.Info.CustomerInfo.ApiAccessorToken, k2i.Info.EnvironmentInfo.GroupName, k2i.Info.AgentInfo.K2validator, k2i.Info.EnvironmentInfo.NodeId, k2i.Info.EnvironmentInfo.RunningEnv, k2i.Info.EnvironmentInfo.ID, filepath.Base(k2i.Info.ApplicationInfo.Cmd), k2i.Info.ApplicationInfo.AppUUID, sha, path, env, outputDir)

	f, err := os.Create(filename)
	if err != nil {
		return
	} else {
		defer f.Close()
	}
	_, err = f.WriteString(str)
	if err != nil {
		return
	}
	return
}

func runCommand(startupScript string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, k2i.CVE_STARPUP, k2i.CVE_STARPUP_COMMAD, startupScript)
	_, err := cmd.CombinedOutput()
	if ctx.Err() != context.DeadlineExceeded {
		return false, ctx.Err()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return false, errors.New("error in cve scan : Timeout")
	}

	if err != nil {
		return false, err
	}
	return true, nil
}

func Untar(sourcefile, target string) (bool, error) {

	file, err := os.Open(sourcefile)

	if err != nil {

		return false, err
	}

	defer file.Close()

	var fileReader io.ReadCloser = file
	if strings.HasSuffix(sourcefile, ".gz") {
		if fileReader, err = gzip.NewReader(file); err != nil {

			return false, err
		}
		defer fileReader.Close()
	}

	tarBallReader := tar.NewReader(fileReader)
	for {
		header, err := tarBallReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return false, err
		}
		filename := filepath.Join(target, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(filename, os.FileMode(header.Mode))

			if err != nil {
				return false, err
			}

		case tar.TypeReg:
			writer, err := os.Create(filename)

			if err != nil {
				return false, err
			}

			io.Copy(writer, tarBallReader)

			err = os.Chmod(filename, os.FileMode(header.Mode))

			if err != nil {
				return false, err
			}

			writer.Close()
		default:
			logger.Errorln("Unable to untar type : %c in file %s", header.Typeflag, filename)
		}
	}

	return true, nil
}

func isFileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	} else {
		return false
	}

}

func getEnvScanSha(filePath string) string {
	var filenames []string
	err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if strings.HasSuffix(path, ".mod") {
			sha1 := mysha(path)
			if sha1 != "" {
				filenames = append(filenames, sha1)
			}
		}
		return nil
	})

	if err != nil {
		return ""

	}
	joinedSha := strings.Join(filenames, "||")
	sum := sha256.Sum256([]byte(joinedSha))
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

func mysha(f string) string {
	b, e := ioutil.ReadFile(f)
	if e != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

func deleteFile() {
	err := os.RemoveAll(k2i.CVE_TAR_SPACE)
	if err != nil {
		logger.Errorln("Unable to delete cve dir ", err)
	}
}
