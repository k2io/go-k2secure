// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_v8wrap

import (
	v8 "github.com/augustoroman/v8"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

var logger = k2i.GetLogger("v8")

type K2v8Context struct {
	v8.Context
}

//go:noinline
func (k *K2v8Context) K2v8Eval_s(j, f string) (*v8.Value, error) {
	logger.Debugln("------------ v8Eval-hook_s", "in hook")
	k2i.K2EvalJS(j)
	value, err := k.K2v8Eval_s(j, f)
	return value, err
}

//go:noinline
func (k *K2v8Context) K2v8Eval(j, f string) (*v8.Value, error) {
	logger.Debugln("------------ v8Eval-hook", "in hook")
	eventID := k2i.K2EvalJS(j)
	if k2i.IsBlockedAPI(eventID) {
		return nil, k2i.K2Exception()
	}
	value, err := k.K2v8Eval_s(j, f)
	k2i.SendExitEvent(eventID, err)
	return value, err
}

func hook() {
	if k2i.DropHook_v8() {
		return
	}

	e := k2i.HookWrapInterface((*v8.Context).Eval, (*K2v8Context).K2v8Eval, (*K2v8Context).K2v8Eval_s)
	k2i.IsHookedLog("(*v8.Context).Eval", e)

}
func init() {
	if k2i.K2OK("k2secure_v8.init") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	hook()
}
