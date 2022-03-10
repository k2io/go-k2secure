// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ws

import (
	"sync"
)

// --------------------------------------------------
// simple circular buffer
// --------------------------------------------------
var maxbuffers = 10240 //entries
var cring [][]byte     //TODO: dynamic
var cringb, cringe int
var wsmutex sync.Mutex
var cringinit = false

// init buffer
func cringMax() int {
	return maxbuffers
}

// count buffer
func cringCount() int {
	if cringEmptyUnlocked() {
		return 0
	}
	if cringFullUnlocked() {
		return maxbuffers
	}
	if cringe > cringb {
		return cringe - cringb + 1
	} else {
		return (cringe + 1) + (maxbuffers - cringb)
	}
}

// init buffer
func cringInit() {
	if !cringinit {
		cring = make([][]byte, maxbuffers, maxbuffers)
		cringb = 0
		cringe = -1
		cringinit = true
	}
}

// full buffer
func cringFullUnlocked() bool {
	ret := (cringb == cringe) && (cringe != -1)
	return ret
}

// empty buffer
func cringEmptyUnlocked() bool {
	ret := (cringe == -1)
	return ret
}

// Remove buffer
func cringPeek() []byte {
	wsmutex.Lock()
	if cringEmptyUnlocked() {
		wsmutex.Unlock()
		return nil
	}
	s := cring[cringb]
	wsmutex.Unlock()
	return s
}

// Remove buffer
func cringRemove() []byte {
	wsmutex.Lock()
	if cringEmptyUnlocked() {
		wsmutex.Unlock()
		return nil
	}
	s := cring[cringb]
	cringb++
	if cringb == cringMax() {
		cringb = 0
	}
	if cringb == cringe {
		cringb = 0
		cringe = -1
		//empty
	}
	wsmutex.Unlock()
	return s
}

// Add buffer
func cringAdd(astr []byte) int {
	if debug_drop_cring {
		return 0
	}
	wsmutex.Lock()
	if cringFullUnlocked() {
		wsmutex.Unlock()
		return -1
	}
	if cringEmptyUnlocked() {
		cringe = 0
		cringb = 0
	}
	cring[cringe] = astr
	cringe++
	if cringe == cringMax() {
		cringe = 0
	}
	wsmutex.Unlock()
	return cringe
}
