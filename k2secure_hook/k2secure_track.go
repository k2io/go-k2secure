// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2utils "github.com/k2io/go-k2secure/v2/internal/k2secure_utils"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	k2iss "github.com/k2io/go-k2secure/v2/k2secure_interface"
	"golang.org/x/sys/unix"
)

// -- cloned from runtime.go/proc.go to get offsets...
//Note: struct stack,gobuf,g16 depenend on golang runtime structures...
type stack struct {
	lo uintptr
	hi uintptr
}
type gobuf struct {
	sp   uintptr
	pc   uintptr
	g    guintptr
	ctxt unsafe.Pointer
	ret  uintptr
	lr   uintptr
	bp   uintptr
}
type muintptr uintptr
type puintptr uintptr
type guintptr uintptr
type waitReason uint8

type dummystack struct {
}
type g16 struct {
	stack        stack
	stackguard0  uintptr
	stackguard1  uintptr
	_panic       *dummystack
	_defer       *dummystack
	m            *dummystack
	sched        gobuf
	syscallsp    uintptr
	syscallpc    uintptr
	stktopsp     uintptr
	param        unsafe.Pointer
	atomicstatus uint32
	stackLock    uint32
	Goid         int64
	schedlink    guintptr
	waitsince    int64
	waitreason   waitReason

	preempt       bool
	preemptStop   bool
	preemptShrink bool

	asyncSafePoint bool

	paniconfault     bool
	gcscandone       bool
	throwsplit       bool
	activeStackChans bool
	parkingOnChan    uint8
	raceignore       int8
	sysblocktraced   bool
	sysexitticks     int64
	traceseq         uint64
	tracelastp       puintptr
	lockedm          muintptr
	sig              uint32
	writebuf         []byte
	sigcode0         uintptr
	sigcode1         uintptr
	sigpc            uintptr
	Gopc             uintptr
	ancestors        *[]dummystack
	startpc          uintptr
	racectx          uintptr
	waiting          *dummystack
	cgoCtxt          []uintptr
	labels           unsafe.Pointer
	timer            *dummystack
	selectDone       uint32
	gcAssistBytes    int64
}

type dummy struct {
}
type dummyg struct {
}
type dummyf struct {
	fn uintptr
}

var threadToid = make(map[int]int64)

//go:noinline
func k2_associateGoRoutine(a, b int64) {
	k2i.K2associateGoRoutine(a, b)
}

//go:noinline
func K2_removeGoRoutine(a int64) {
	k2i.K2removeGoRoutine(a)
}

//go:noinline
func K2_newproc15(fn *dummyf, argp unsafe.Pointer, narg int32, callergp *g16, callerpc uintptr) *g16 {
	retrieval := K2_newproc15_s(fn, argp, narg, callergp, callerpc)

	if retrieval != nil && callergp != nil {
		aa := callergp.Goid
		bb := retrieval.Goid
		k2_associateGoRoutine(aa, bb)
	}
	return retrieval
}

//go:noinline
func K2_newproc15_s(fn *dummyf, argp unsafe.Pointer, narg int32, callergp *g16, callerpc uintptr) *g16 {
	retrieval := K2_newproc15_s(fn, argp, narg, callergp, callerpc)

	if retrieval != nil && callergp != nil {
		aa := callergp.Goid
		bb := retrieval.Goid
		k2_associateGoRoutine(aa, bb)
	}
	return retrieval
}

//go:noinline
func K2_newproc18(fn *dummyf, callergp *g16, callerpc uintptr) *g16 {
	retrieval := K2_newproc18_s(fn, callergp, callerpc)

	if retrieval != nil && callergp != nil {
		aa := callergp.Goid
		bb := retrieval.Goid
		k2_associateGoRoutine(aa, bb)
	}
	return retrieval
}

//go:noinline
func K2_newproc18_s(fn *dummyf, callergp *g16, callerpc uintptr) *g16 {
	retrieval := K2_newproc18_s(fn, callergp, callerpc)

	if retrieval != nil && callergp != nil {
		aa := callergp.Goid
		bb := retrieval.Goid
		k2_associateGoRoutine(aa, bb)
	}
	return retrieval
}

//go:noinline
func K2_runqput13(_p_ *interface{}, callergp *g16, next bool) {
	stack := printStackTrace()
	if next && callergp != nil && strings.Contains(stack, "K2_newproc13") {
		id := unix.Gettid()
		i := threadToid[id]
		delete(threadToid, id)
		k2_associateGoRoutine(i, callergp.Goid)
	}
	K2_runqput13_s(_p_, callergp, next)
	return
}

//go:noinline
func K2_runqput13_s(_p_ *interface{}, callergp *g16, next bool) {
	stack := printStackTrace()
	if next && callergp != nil && strings.Contains(stack, "K2_newproc13") {
		id := unix.Gettid()
		i := threadToid[id]
		delete(threadToid, id)
		k2_associateGoRoutine(i, callergp.Goid)
	}
	K2_runqput13_s(_p_, callergp, next)
	return
}

func K2_newproc13(fn *dummyf, argp *uint8, narg int32, callergp *g16, callerpc uintptr) {
	if callergp != nil {
		aa := callergp.Goid
		threadToid[unix.Gettid()] = aa
	}
	K2_newproc13_s(fn, argp, narg, callergp, callerpc)
	return
}

//go:noinline
func K2_newproc13_s(fn *dummyf, argp *uint8, narg int32, callergp *g16, callerpc uintptr) {
	if callergp != nil {
		aa := callergp.Goid
		threadToid[unix.Gettid()] = aa
	}
	K2_newproc13_s(fn, argp, narg, callergp, callerpc)
	return
}

func initTrackerhook() error {

	currentVersion := k2utils.GetCurrentGoVersion()
	var e error

	if currentVersion < 15 {
		_, e = k2i.HookWrapRawNamed("runtime.runqput", K2_runqput13, K2_runqput13_s)
		_, e = k2i.HookWrapRawNamed("runtime.newproc1", K2_newproc13, K2_newproc13_s)
		logging.IsHooked("runtime.K2_runqput13", e)
	} else if currentVersion > 17 {
		_, e = k2i.HookWrapRawNamed("runtime.newproc1", K2_newproc18, K2_newproc18_s)
		logging.IsHooked("runtime.newproc1_18", e)
	} else {
		_, e = k2i.HookWrapRawNamed("runtime.newproc1", K2_newproc15, K2_newproc15_s)
		logging.IsHooked("runtime.newproc1_15", e)
	}

	return e
}

func PresentStack(frames *runtime.Frames, method string) (string, string, string, string, []string, string) {
	userfile := "NoFILE"
	usermethod := "NoMethod"
	userline := "0"
	srcmethod := "noMethod"
	id := k2i.Identity()
	j := ""
	//comma:=""
	count := 0
	apiId := ""
	apiIdsep := ""
	pf := ""
	pm := ""

	var arg []string

	isUserSet := false
	for true {
		frame, more := frames.Next()
		m := frame.Function
		f := frame.File
		line := strconv.Itoa(frame.Line)
		// k2i.K2log("PresentStack: frame... ",f,m,line)
		if count == 0 {
			u := frame.Entry
			check, k := k2lineMapLookup(u)
			if check {
				m = k.A
				f = k.B
				line = k.C
				srcmethod = m
			}
		} else if (count >= 1) && !isUserSet && isUser(f, m, pf, pm) {
			userfile = f //user func is caller of our hook API
			usermethod = m
			userline = line
			isUserSet = true
		}

		if !strings.HasPrefix(m, id) {
			apiId = apiId + apiIdsep + m
			apiIdsep = "||"
			j = m + "(" + f + ":" + line + ")"
			arg = append(arg, j)

			// comma=","
		}
		count++
		pf = f //previous
		pm = m
		if !more {
			if (len(userfile) == len(usermethod)) && (len(usermethod) == 0) {
				userfile = f
				usermethod = m
				userline = line
			}
			break
		}
	}
	j = "[" + j + "]"
	apiId = StringSHA256(apiId + "||" + method)
	return srcmethod, userfile, usermethod, userline, arg, apiId
}

var k2lineMap = make(map[uintptr]k2iss.Tuple, 0)

func k2lineMapLookup(u uintptr) (bool, k2iss.Tuple) {
	unkTuple := k2iss.Tuple{A: "unknownMethod", B: "unknownFile", C: "unknownLine"}
	t, ok := k2lineMap[u]
	if !ok {
		return false, unkTuple
	}
	return true, t
}

func StringSHA256(f string) string {
	sum := sha256.Sum256([]byte(f))
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

func isUser(aMethod, aFile, prevMethod, prevFile string) bool {

	// either reach main package OR different prefix.
	i := strings.LastIndex(aMethod, "/")
	aprefix := aMethod
	if i >= 0 {
		aprefix = aMethod[:i]
	}
	j := strings.LastIndex(prevMethod, "/")
	pprefix := prevMethod
	if j >= 0 {
		pprefix = prevMethod[:j]
	}
	//k2i.K2log(" isUser check ",aMethod,aFile,prevMethod,prevFile,aprefix,pprefix)
	if aprefix != pprefix {
		// k2i.K2log(" isUser check -- prefix mismatch",aMethod,aFile,prevMethod,prevFile,aprefix,pprefix)
		return true
	}
	if strings.HasPrefix(aMethod, "main.") {
		// k2i.K2log(" isUser check -- main.*",aMethod,aFile,prevMethod,prevFile,aprefix,pprefix)
		return true
	}
	return false
}

func printStackTrace() string {
	pc := make([]uintptr, 10)
	n := runtime.Callers(4, pc)
	frames := runtime.CallersFrames(pc[:n])
	_, _, _, _, stkjson, _ := PresentStack(frames, "")
	return strings.Join(stkjson, "::")
}
