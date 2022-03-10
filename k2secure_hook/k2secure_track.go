// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"unsafe"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
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

//go:noinline
func k2_associateGoRoutine(a, b int64) {
	k2i.K2associateGoRoutine(a, b)
}

//go:noinline
func K2_removeGoRoutine(a int64) {
	k2i.K2removeGoRoutine(a)
}

//go:noinline
func K2_newproc1(fn *dummyf, argp unsafe.Pointer, narg int32, callergp *g16, callerpc uintptr) *g16 {
	retrieval := K2_newproc1_s(fn, argp, narg, callergp, callerpc)

	if retrieval != nil && callergp != nil {
		aa := callergp.Goid
		bb := retrieval.Goid
		k2_associateGoRoutine(aa, bb)
	}
	return retrieval
}

//go:noinline
func K2_newproc1_s(fn *dummyf, argp unsafe.Pointer, narg int32, callergp *g16, callerpc uintptr) *g16 {
	retrieval := K2_newproc1_s(fn, argp, narg, callergp, callerpc)

	if retrieval != nil && callergp != nil {
		aa := callergp.Goid
		bb := retrieval.Goid
		k2_associateGoRoutine(aa, bb)
	}
	return retrieval
}

func initTrackerhook() error {

	_, e := k2i.HookWrapRawNamed("runtime.newproc1", K2_newproc1, K2_newproc1_s)
	logging.IsHooked("runtime.newproc1", e)
	return e
}
