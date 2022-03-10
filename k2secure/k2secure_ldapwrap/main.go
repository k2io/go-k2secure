// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ldapwrap

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

var logger = k2i.GetLogger("ldap")

type k2ldapConnstruct struct {
	ldap.Conn
}

// RFC4515 defines encoding for ldap
func UnescapeRFC4515validJSON(a string) string {
	logger.Debugln("ldapString incoming:", a)
	r := a
	r = strings.Replace(r, "\\2a", "*", -1)
	r = strings.Replace(r, "\\2A", "*", -1)
	r = strings.Replace(r, "\\28", "(", -1)
	r = strings.Replace(r, "\\29", ")", -1)
	logger.Debugln("ldapString Outgoing:", r)
	return r
}

//go:noinline
func (l *k2ldapConnstruct) K2ldapConnSearch_s(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	logger.Debugln("------------ k2ldap.Conn.Search_s-hook", "in hook")
	if searchRequest != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*searchRequest).Filter)
		k2i.K2ldap(xm)
	}
	res, err := l.K2ldapConnSearch_s(searchRequest)
	return res, err
}

//go:noinline
func (l *k2ldapConnstruct) K2ldapConnSearch(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	logger.Debugln("------------ k2ldap.Conn.Search-hook", "in hook")
	var eventID = k2i.GetDummyEvent()
	if searchRequest != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*searchRequest).Filter)
		eventID = k2i.K2ldap(xm)
	}
	res, err := l.K2ldapConnSearch_s(searchRequest)
	k2i.SendExitEvent(eventID, err)
	return res, err
}

//go:noinline
func (l *k2ldapConnstruct) K2ldapConnModify_s(mReq *ldap.ModifyRequest) error {
	logger.Debugln("------------ k2ldap.Conn.K2ldapConnModify_s-hook", "in hook")
	if mReq != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*mReq).DN)
		k2i.K2ldap(xm)
	}
	err := l.K2ldapConnModify_s(mReq)
	return err
}

//go:noinline
func (l *k2ldapConnstruct) K2ldapConnModify(mReq *ldap.ModifyRequest) error {
	logger.Debugln("------------ k2ldap.Conn.K2ldapConnModify-hook", "in hook")
	var eventID = k2i.GetDummyEvent()
	if mReq != nil {
		xm := make(map[string]string, 0)
		xm["filter"] = UnescapeRFC4515validJSON((*mReq).DN)
		eventID = k2i.K2ldap(xm)
	}
	err := l.K2ldapConnModify_s(mReq)
	k2i.SendExitEvent(eventID, err)
	return err
}

func hook() {
	if k2i.DropHook_ldap() {
		return
	}
	e := k2i.HookWrapInterface((*ldap.Conn).Search, (*k2ldapConnstruct).K2ldapConnSearch, (*k2ldapConnstruct).K2ldapConnSearch_s)
	k2i.IsHookedLog("(*ldap.Conn).Search", e)
	e = k2i.HookWrapInterface((*ldap.Conn).Modify, (*k2ldapConnstruct).K2ldapConnModify, (*k2ldapConnstruct).K2ldapConnModify_s)
	k2i.IsHookedLog("(*ldap.Conn).Modify", e)
	return
}
func init() {
	if k2i.K2OK("k2secure_go-ldap.init") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	hook()
}
