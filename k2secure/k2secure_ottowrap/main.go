// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ottowrap

import (
	"bytes"
	"io"

	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	"github.com/robertkrimen/otto"
)

var logger = k2i.GetLogger("otto")

func src2string(s interface{}) string {
	//"github.com/robertkrimen/otto"o
	//src may be a string, a byte slice, a bytes.Buffer, or an io.Reader, but it MUST always be in UTF-8.
	logger.Debugln("in src2string - otto")
	//src may also be a Script.
	switch s.(type) {
	case nil:
		return ""
	case string:
		ss, ok := s.(string)
		if ok {
			return string(ss)
		}
	case []byte:
		b, ok := s.([]byte)
		if ok {
			return string(b)
		}
	case bytes.Buffer:
		bb, ok := s.(bytes.Buffer)
		if ok {
			return (&bb).String()
		}
	case io.Reader:
		ir, ok := s.(io.Reader)
		if ok {
			buff := make([]byte, 4096)
			_, err := ir.Read(buff)
			if err == nil {
				return string(buff)
			} else {
				logger.Errorln("k2secure_otto: failed to read ioReader src", ir)
			}
		}
	}
	return ""
}

type K2ottoStruct struct {
	otto.Otto
}

//go:noinline
func (k K2ottoStruct) K2ottoRun_s(src interface{}) (otto.Value, error) {
	logger.Debugln("------------ otto.Run-hook_s", "in hook")
	if src != nil {
		e := src2string(src)
		if e != "" {
			k2i.K2EvalJS(e)
		}
	}
	value, err := k.K2ottoRun_s(src)
	return value, err
}

//go:noinline
func (k K2ottoStruct) K2ottoRun(src interface{}) (otto.Value, error) {
	logger.Debugln("------------ otto.Run-hook", "in hook")
	var eventID = k2i.GetDummyEvent()
	if src != nil {
		e := src2string(src)
		if e != "" {
			eventID = k2i.K2EvalJS(e)
			if k2i.IsBlockedAPI(eventID) {
				return nil, k2i.K2Exception()
			}
		}
	}
	value, err := k.K2ottoRun_s(src)
	k2i.SendExitEvent(eventID, err)
	return value, err
}

//go:noinline
func (k K2ottoStruct) K2ottoEval_s(src interface{}) (otto.Value, error) {
	logger.Debugln("------------ otto.Eval-hook_s", "in hook")
	if src != nil {
		e := src2string(src)
		if e != "" {
			k2i.K2EvalJS(e)
		}
	}
	value, err := k.K2ottoEval_s(src)
	return value, err
}

//go:noinline
func (k K2ottoStruct) K2ottoEval(src interface{}) (otto.Value, error) {
	logger.Debugln("------------ otto.Eval-hook", "in hook")
	var eventID = k2i.GetDummyEvent()
	if src != nil {
		e := src2string(src)
		if e != "" {
			eventID = k2i.K2EvalJS(e)
			if k2i.IsBlockedAPI(eventID) {
				return nil, k2i.K2Exception()
			}
		}
	}
	value, err := k.K2ottoEval_s(src)
	k2i.SendExitEvent(eventID, err)
	return value, err
}

func hook() {
	if k2i.DropHook_otto() {
		return
	}
	e := k2i.HookWrapInterface((otto.Otto).Run, (K2ottoStruct).K2ottoRun, (K2ottoStruct).K2ottoRun_s)
	k2i.IsHookedLog("(otto.Otto).Run", e)
	e = k2i.HookWrapInterface((otto.Otto).Eval, (K2ottoStruct).K2ottoEval, (K2ottoStruct).K2ottoEval_s)
	k2i.IsHookedLog("(otto.Otto).Eval", e)
}
func init() {
	if k2i.K2OK("k2secure_otto.init") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	hook()
}
