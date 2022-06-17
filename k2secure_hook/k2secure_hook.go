// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"os"
	"os/exec"
	"reflect"
	"strings"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

//go:noinline
func K2OpenFile_s(name string, flag int, perm os.FileMode) (*os.File, error) {
	eventId := k2i.K2openFile(name, flag)
	file, err := K2OpenFile_s(name, flag, perm)
	k2i.SendExitEvent(eventId, err)
	return file, err
}

//go:noinline
func K2OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	eventId := k2i.K2openFile(name, flag)
	if k2i.IsBlockedAPI(eventId) {
		return nil, k2i.K2Exception()
	}
	file, err := K2OpenFile_s(name, flag, perm)
	k2i.SendExitEvent(eventId, err)
	return file, err
}

//go:noinline
func K2Remove(name string) error {
	eventId := k2i.K2RemoveFile(name)
	if k2i.IsBlockedAPI(eventId) {
		return k2i.K2Exception()
	}
	err := K2Remove_s(name)
	k2i.SendExitEvent(eventId, err)
	return err
}

//go:noinline
func K2Remove_s(name string) error {

	eventId := k2i.K2RemoveFile(name)
	err := K2Remove_s(name)
	k2i.SendExitEvent(eventId, err)
	return err

}

//go:noinline
func K2Exit_s(code int) {
	k2i.K2EndHook()
	k2i.K2EndHook()
	k2i.K2EndHook()
	return
}

//go:noinline
func K2Exit(code int) {
	logger.Debugln("Hook Called : ", "syscall.Exit")
	k2i.K2preExit(code)
	K2Exit_s(code)
}

//go:noinline
func K2StartProcess_s(name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	logger.Debugln("Hook Called : ", "os.StartProcess_s")
	k2i.K2preCommand(strings.Join(argv, " "))
	a, b := K2StartProcess_s(name, argv, attr)
	return a, b
}

//go:noinline
func K2StartProcess(name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	logger.Debugln("Hook Called : ", "os.StartProcess")
	eventId := k2i.K2preCommand(strings.Join(argv, " "))
	if k2i.IsBlockedAPI(eventId) {
		return nil, k2i.K2Exception()
	}
	out, err := K2StartProcess_s(name, argv, attr)
	k2i.SendExitEvent(eventId, err)
	return out, err
}

type k2cmd struct {
	exec.Cmd
}

//go:noinline
func (c *k2cmd) k2Start() error {
	eventId := k2i.GetDummyEvent()
	logger.Debugln("Hook Called : ", "(*exec.Cmd).Start")
	if c != nil {
		err := reflect.ValueOf(c).Elem().FieldByName("lookPathErr")
		if err.IsValid() {
			if !err.IsNil() {
				eventId = k2i.K2preCommand(strings.Join(c.Args, " "))
				if k2i.IsBlockedAPI(eventId) {
					return k2i.K2Exception()
				}
			}
		}
	}
	a := c.k2Start_s()
	if c != nil {
		err := reflect.ValueOf(c).Elem().FieldByName("lookPathErr")
		if err.IsValid() {
			if !err.IsNil() {
				k2i.SendExitEvent(eventId, a)
			}
		}
	}
	return a
}

//go:noinline
func (c *k2cmd) k2Start_s() error {
	logger.Debugln("Hook Called : ", "(*exec.Cmd).Start_s")
	if c != nil {
		err := reflect.ValueOf(c).Elem().FieldByName("lookPathErr")
		if err.IsValid() {
			if !err.IsNil() {
				k2i.K2preCommand(strings.Join(c.Args, " "))
			}
		}
	}
	a := c.k2Start_s()
	return a
}
func initFilehooks() {
	if debug_drop_hooks || debug_drop_file_hooks {
		return
	}
	e := k2i.HookWrap(os.OpenFile, K2OpenFile, K2OpenFile_s)
	e = k2i.HookWrap(os.Remove, K2Remove, K2Remove_s)
	logging.IsHooked("os.OpenFile", e)
}

func initOshooks() {
	if debug_drop_hooks || debug_drop_os_hooks {
		return
	}
	// e := k2i.HookWrap(syscall.Exit, K2Exit, K2Exit_s)
	// logging.IsHooked("syscall.Exit", e)
	e := k2i.HookWrap(os.StartProcess, K2StartProcess, K2StartProcess_s)
	logging.IsHooked("os.StartProcess", e)
	e = k2i.HookWrapInterface((*exec.Cmd).Start, (*k2cmd).k2Start, (*k2cmd).k2Start_s)
	logging.IsHooked("(*exec.Cmd).Start", e)
}
