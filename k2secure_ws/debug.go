// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ws

// debugging flags pff by default
var debug_drop_cring = false
var debug_drop_send = false
var debug_ws_off = false
var debug_ws_thread_off = false
var debug_ftp_log_upload_off = false

func SetDropEventBuffer()     { debug_drop_cring = true; verbose("eventbuffer", "T") }
func SetDropEventSend()       { debug_drop_send = true; verbose("eventSend", "T") }
func SetDropWebsocket()       { debug_ws_off = true; verbose("Websocket", "T") }
func SetDropWebsocketThread() { debug_ws_thread_off = true; verbose("WebsocketThread", "T") }
func SetDropFtpLogUpload()    { debug_ftp_log_upload_off = true; verbose("FtpLogUpload", "T") }

func verbose(a, b string) {
	println("k2secure_ws:init_opts:DISABLED" + a + " -- " + b)
}

// --------------------------------------------------------
// Func init_opts - debug opts etc.
// called from package init()
// --------------------------------------------------------
func init_opts() { // turn-on/off here
	//SetDropEventBuffer()
	//SetDropEventSend()
	//SetDropWebsocket()
	//SetDropWebsocketThread()
}
