// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_jsonquerywrap

import (
	"reflect"

	"github.com/antchfx/jsonquery"
	"github.com/antchfx/xpath"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

var logger = k2i.GetLogger("jsonquery")

//go:noinline
func K2JsonquerySelectorAll_s(top *jsonquery.Node, selector *xpath.Expr) []*jsonquery.Node {
	logger.Debugln("------------ k2Json.K2JsonquerySelectorAll_s", "in hook")
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		k2i.K2xpathEval(fv.String())
	}
	a := K2JsonquerySelectorAll_s(top, selector)
	return a
}

//go:noinline
func K2JsonquerySelectorAll(top *jsonquery.Node, selector *xpath.Expr) []*jsonquery.Node {
	logger.Debugln("------------ k2Json.K2JsonquerySelectorAll", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
		if k2i.IsBlockedAPI(eventID) {
			return nil
		}
	}
	a := K2JsonquerySelectorAll_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func K2JsonquerySelector_s(top *jsonquery.Node, selector *xpath.Expr) *jsonquery.Node {
	logger.Debugln("------------ k2Json.K2JsonquerySelector_s", "in hook")
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		k2i.K2xpathEval(fv.String())
	}
	a := K2JsonquerySelector_s(top, selector)
	return a
}

//go:noinline
func K2JsonquerySelector(top *jsonquery.Node, selector *xpath.Expr) *jsonquery.Node {
	logger.Debugln("------------ k2Json.K2JsonquerySelector", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
		if k2i.IsBlockedAPI(eventID) {
			return nil
		}
	}
	a := K2JsonquerySelector_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

func applyXpathHooks() {
	logger.Infoln("Jsonquery pluginStart Started")
	if k2i.DropHook_xmlquery() {
		logger.Infoln("Drop Jsonquery hooking")
		return
	}
	e := k2i.HookWrap(jsonquery.QuerySelector, K2JsonquerySelector, K2JsonquerySelector_s)
	k2i.IsHookedLog("jsonquery.QuerySelector", e)

	e = k2i.HookWrap(jsonquery.QuerySelectorAll, K2JsonquerySelectorAll, K2JsonquerySelectorAll_s)
	k2i.IsHookedLog("jsonquery.QuerySelectorAll", e)

	logger.Infoln("jsonquery pluginStart completed")
}

func init() {
	if k2i.K2OK("jsonquery") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	applyXpathHooks()
}
