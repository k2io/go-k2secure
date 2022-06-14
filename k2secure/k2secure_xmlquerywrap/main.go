// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_xmlquerywrap

import (
	"reflect"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

var logger = k2i.GetLogger("xmlquery")

//go:noinline
func K2xmlQuerySelectorAll_s(top *xmlquery.Node, selector *xpath.Expr) []*xmlquery.Node {
	logger.Debugln("------------ k2xpath.K2xmlQuerySelectorAll", "in hook")
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		k2i.K2xpathEval(fv.String())
	}
	a := K2xmlQuerySelectorAll_s(top, selector)
	return a
}

//go:noinline
func K2xmlQuerySelectorAll(top *xmlquery.Node, selector *xpath.Expr) []*xmlquery.Node {
	logger.Debugln("------------ k2xpath.K2xmlQuerySelectorAll", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
		if k2i.IsBlockedAPI(eventID) {
			return nil
		}
	}
	a := K2xmlQuerySelectorAll_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func K2xmlQuerySelector_s(top *xmlquery.Node, selector *xpath.Expr) *xmlquery.Node {
	logger.Debugln("------------ k2xpath.K2xmlQuerySelector", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
	}
	a := K2xmlQuerySelector_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func K2xmlQuerySelector(top *xmlquery.Node, selector *xpath.Expr) *xmlquery.Node {
	logger.Debugln("------------ k2xpath.K2xmlQuerySelector", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
		if k2i.IsBlockedAPI(eventID) {
			return nil
		}
	}
	a := K2xmlQuerySelector_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

func applyXpathHooks() {
	logger.Infoln("xmlquery pluginStart Started")
	if k2i.DropHook_xmlquery() {
		logger.Infoln("Drop xmlquery hooking")
		return
	}
	e := k2i.HookWrap(xmlquery.QuerySelector, K2xmlQuerySelector, K2xmlQuerySelector_s)
	k2i.IsHookedLog("xmlquery.QuerySelector", e)

	e = k2i.HookWrap(xmlquery.QuerySelectorAll, K2xmlQuerySelectorAll, K2xmlQuerySelectorAll_s)
	k2i.IsHookedLog("xmlquery.QuerySelectorAll", e)

	logger.Infoln("xmlquery pluginStart completed")
}
func init() {
	if k2i.K2OK("xmlquery") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	applyXpathHooks()
}
