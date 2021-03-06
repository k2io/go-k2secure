// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_grpcwrap

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	grpccurl "github.com/fullstorydev/grpcurl"
	k2ntercept "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var confFile = ""

const confFileName = "/k2GrpcConf.json"

var confFilePath = ""

var confImportPaths []string
var confImportFiles []string

// ---- GRPC Conf -----

type GrpcConf struct {
	ImportPaths []string `json:"importPaths"`
	ImportFiles []string `json:"importedFiles"`
}

func checkAndCreateconfFile() error {
	logger.Debugln("Creating Grpc Config file")
	deployedPath, e := filepath.Abs(k2i.Info.ApplicationInfo.Cmd)
	if e != nil {
		deployedPath = k2i.Info.ApplicationInfo.Cmd
	}
	deployedPath = filepath.Dir(deployedPath)
	confFile = deployedPath + confFileName
	confFilePath = confFile
	if k2ntercept.IsFileExist(confFile) {
		plan, err := ioutil.ReadFile(confFile)
		if err != nil {
			return err
		}
		var conf GrpcConf
		err = json.Unmarshal(plan, &conf)
		if err != nil {
			return err
		}
		confImportPaths = conf.ImportPaths
		confImportFiles = conf.ImportFiles
		return nil
	}

	var importPaths []string
	var importFiles []string

	err := filepath.Walk(deployedPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".proto" {
			abs, err := filepath.Abs(path)
			if err == nil {
				importPaths = append(importPaths, filepath.Dir(abs))
				importFiles = append(importFiles, filepath.Base(abs))
			}
		}
		return nil
	})
	if err != nil {
		logger.Errorln("Error during Creating Grpc Conf file")
	}
	if len(importPaths) > 0 && len(importFiles) > 0 {
		_, refSourceErr := grpccurl.DescriptorSourceFromProtoFiles(importPaths, importFiles...)
		if refSourceErr != nil {
			importPaths = importPaths[:0]
			importFiles = importFiles[:0]
		}
	}
	var conf GrpcConf

	if len(importPaths) == 0 && len(importFiles) == 0 {
		importPaths = append(importPaths, "")
		importFiles = append(importFiles, "")
	}
	conf.ImportPaths = importPaths
	conf.ImportFiles = importFiles
	file, err := json.MarshalIndent(conf, "", " ")
	if err == nil {
		err = ioutil.WriteFile(confFile, file, 0644)
		confImportPaths = conf.ImportPaths
		confImportFiles = conf.ImportFiles
	}
	if err != nil {
		return err
	} else {
		return nil
	}
}
