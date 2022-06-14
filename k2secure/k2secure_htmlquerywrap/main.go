// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_htmlquerywrap

import (
	"reflect"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xpath"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	"golang.org/x/net/html"
)

var logger = k2i.GetLogger("htmlQuery")

//go:noinline
func K2HtmlquerySelectorAll_s(top *html.Node, selector *xpath.Expr) []*html.Node {
	logger.Debugln("------------ k2html.K2HtmlquerySelectorAll_s", "in hook")
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		k2i.K2xpathEval(fv.String())
	}
	a := K2HtmlquerySelectorAll_s(top, selector)
	return a
}

//go:noinline
func K2HtmlquerySelectorAll(top *html.Node, selector *xpath.Expr) []*html.Node {
	logger.Debugln("------------ k2html.K2HtmlquerySelectorAll", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
		if k2i.IsBlockedAPI(eventID.ID) {
			return nil
		}
	}
	a := K2HtmlquerySelectorAll_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func K2HtmlquerySelector_s(top *html.Node, selector *xpath.Expr) *html.Node {
	logger.Debugln("------------ k2html.K2HtmlquerySelector_s", "in hook")
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		k2i.K2xpathEval(fv.String())
	}
	a := K2HtmlquerySelector_s(top, selector)
	return a
}

//go:noinline
func K2HtmlquerySelector(top *html.Node, selector *xpath.Expr) *html.Node {
	logger.Debugln("------------ k2html.K2HtmlquerySelector", "in hook")
	var eventID = k2i.GetDummyEvent()
	if selector != nil {
		fv := reflect.ValueOf(selector).Elem().FieldByName("s")
		eventID = k2i.K2xpathEval(fv.String())
		if k2i.IsBlockedAPI(eventID.ID) {
			return nil
		}
	}
	a := K2HtmlquerySelector_s(top, selector)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

func applyXpathHooks() {
	logger.Infoln("Htmlquery pluginStart Started")
	if k2i.DropHook_xmlquery() {
		logger.Infoln("Drop Htmlquery hooking")
		return
	}
	e := k2i.HookWrap(htmlquery.QuerySelector, K2HtmlquerySelector, K2HtmlquerySelector_s)
	k2i.IsHookedLog("htmlquery.QuerySelector", e)

	e = k2i.HookWrap(htmlquery.QuerySelectorAll, K2HtmlquerySelectorAll, K2HtmlquerySelectorAll_s)
	k2i.IsHookedLog("htmlquery.QuerySelectorAll", e)

	logger.Infoln("htmlquery pluginStart completed")
}
func init() {
	if k2i.K2OK("htmlquery") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	applyXpathHooks()
}
