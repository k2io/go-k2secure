// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import "github.com/k2io/go-k2secure/v2/k2secure_intercept"

var debug_drop_hooks = false
var debug_drop_sql_hooks = false
var debug_drop_file_hooks = false
var debug_drop_os_hooks = false
var debug_drop_outgoing_hooks = false
var debug_drop_incoming_hooks = false

func verbose(a, b string) {
	println("k2secure_hook: DISABLE " + a + "--" + b)
}
func SetDropHooks()         { debug_drop_hooks = true; verbose("all", "TRUE") }
func SetDropHook_sql()      { debug_drop_sql_hooks = true; verbose("sql", "TRUE") }
func SetDropHook_file()     { debug_drop_file_hooks = true; verbose("file", "TRUE") }
func SetDropHook_os()       { debug_drop_os_hooks = true; verbose("OS", "TRUE") }
func SetDropHook_outgoing() { debug_drop_outgoing_hooks = true; verbose("out", "TRUE") }
func SetDropHook_incoming() { debug_drop_incoming_hooks = true; verbose("in", "TRUE") }

func init_opt_hooks() {
	// SetDropHooks() //drop All Hooks
	debug_drop_hooks = k2secure_intercept.DropHooksRequest()
	if debug_drop_hooks { // drop All Hooks
		k2secure_intercept.SetDropHook_ldap()
		k2secure_intercept.SetDropHook_mongo()
		k2secure_intercept.SetDropHook_xpath()
		k2secure_intercept.SetDropHook_v8()
		k2secure_intercept.SetDropHook_otto()
		k2secure_intercept.SetDropHook_xquery()
		k2secure_intercept.SetDropHook_xmlquery()
		k2secure_intercept.SetDropHook_grpc()
		SetDropHook_sql()
		SetDropHook_file()
		SetDropHook_os()
		SetDropHook_outgoing()
		SetDropHook_incoming()
	} else {
		// k2secure_intercept.SetDropHook_ldap()
		// k2secure_intercept.SetDropHook_mongo()
		// k2secure_intercept.SetDropHook_xpath()
		// k2secure_intercept.SetDropHook_v8()
		// k2secure_intercept.SetDropHook_otto()
		// k2secure_intercept.SetDropHook_xquery()
		// k2secure_intercept.SetDropHook_xmlquery()
		// k2secure_intercept.SetDropHook_grpc()
		// SetDropHook_sql()
		// SetDropHook_file()
		// SetDropHook_os()
		// SetDropHook_outgoing()
		// SetDropHook_incoming()
	}
}
