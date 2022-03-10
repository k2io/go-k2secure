// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_intercept

var drop_ldap = false
var drop_xpath = false
var drop_xquery = false
var drop_xmlquery = false
var drop_mongo = false
var drop_v8 = false
var drop_otto = false
var drop_grpc = false

func DropHook_ldap() bool     { return drop_ldap }
func DropHook_xpath() bool    { return drop_xpath }
func DropHook_xquery() bool   { return drop_xquery }
func DropHook_xmlquery() bool { return drop_xmlquery }
func DropHook_mongo() bool    { return drop_mongo }
func DropHook_v8() bool       { return drop_v8 }
func DropHook_otto() bool     { return drop_otto }
func DropHook_grpc() bool     { return drop_grpc }

func SetDropHook_ldap()     { drop_ldap = true; verbose("ldap", "TRUE") }
func SetDropHook_xpath()    { drop_xpath = true; verbose("xpath", "TRUE") }
func SetDropHook_xmlquery() { drop_xmlquery = true; verbose("xmlquery", "TRUE") }
func SetDropHook_xquery()   { drop_xquery = true; verbose("xquery", "TRUE") }
func SetDropHook_mongo()    { drop_mongo = true; verbose("mongo", "TRUE") }
func SetDropHook_v8()       { drop_v8 = true; verbose("v8", "TRUE") }
func SetDropHook_otto()     { drop_otto = true; verbose("otto", "TRUE") }
func SetDropHook_grpc()     { drop_otto = true; verbose("grpc", "TRUE") }

func verbose(a, b string) {
	println("k2secure_optional: DISABLE " + a + "--" + b)
}
