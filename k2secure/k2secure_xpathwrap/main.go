// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_xpathwrap

import (
	"github.com/antchfx/xpath"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

var logger = k2i.GetLogger("xpath")

type K2xpathExpr struct {
	x xpath.Expr
}

//go:noinline
func (e *K2xpathExpr) K2xpathExprEvaluate_s(root xpath.NodeNavigator) interface{} {
	logger.Debugln("------------ xpath.ExprEvaluate-hook", "in hook")
	eventID := k2i.K2xpathEval((root).Value())
	a := e.K2xpathExprEvaluate_s(root)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

//go:noinline
func (e *K2xpathExpr) K2xpathExprEvaluate(root xpath.NodeNavigator) interface{} {
	logger.Debugln("------------ xpath.ExprEvaluate-hook", "in hook")
	eventID := k2i.K2xpathEval((root).Value())
	a := e.K2xpathExprEvaluate_s(root)
	if a != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return a
}

func applyXpathHooks() {
	logger.Infoln("xpath pluginStart Started")
	if k2i.DropHook_xpath() {
		logger.Infoln("Drop xmlquery hooking")
		return
	}
	e := k2i.HookWrapInterface((*xpath.Expr).Evaluate, (*K2xpathExpr).K2xpathExprEvaluate, (*K2xpathExpr).K2xpathExprEvaluate_s)
	k2i.IsHookedLog("(*xpath.Expr).Evaluate", e)

	logger.Infoln("xpath pluginStart completed")
}
func init() {
	if k2i.K2OK("k2secure_xpath.init") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	applyXpathHooks()
}
