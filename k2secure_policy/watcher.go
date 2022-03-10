// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_policy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_interface"
)

var (
	watcher *fsnotify.Watcher
)

func Initialise() (err error) {
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		logger.WithError(err).Errorln("Unable to start FS watcher")
		return
	}
	go func() {
		defer logger.Infoln("FS event listener existing")
		logger.Infoln("FS watcher started")
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				eventHandler(event)

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.WithError(err).Errorln("Error while reading FS events")
			}
		}
	}()
	syscall.Umask(0)
	err = os.Chmod(K2_AGENT_POLICY_PATH, 0777)
	if err != nil {
		logger.Errorln("Not able to change conf file permission")
	}
	err = watcher.Add(filepath.Dir(K2_AGENT_POLICY_PATH))
	if err != nil {
		logger.WithError(err).WithField("path", K2_AGENT_POLICY_PATH).Errorln("Unable to set FS watcher for config")
		return
	}
	return
}

func eventHandler(event fsnotify.Event) {
	switch event.Op {
	case event.Op & fsnotify.Write:
		logger.WithField("event", event).Debugln("FS write event received")
		if strings.HasSuffix(K2_AGENT_POLICY_PATH, event.Name) {
			ReadAgentPolicy()
		}
	case fsnotify.Remove:
		if strings.HasSuffix(K2_AGENT_POLICY_PATH, event.Name) {
			logger.Errorln("Policy file removed creating new policy with default config")
			writeAgentPolicy(k2i.Info.GlobalData)

			err := os.Chmod(K2_AGENT_POLICY_PATH, 0777)
			if err != nil {
				logger.Errorln("Not able to change conf file permission")
			}
		}
	}
}

func Close() {
	if watcher != nil {
		watcher.Close()
	}
}
