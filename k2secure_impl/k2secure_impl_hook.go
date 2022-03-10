// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_impl

import (
	"debug/elf"
	"errors"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"github.com/k2io/hookingo"
)

var symb map[string]uintptr

// --------------------------------------------------------------------------
// Func HookWrap - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func (k K2secureimpl) HookWrap(from, to, toc interface{}) error {
	hookingo.SetDebug(false)
	h, e1 := hookingo.ApplyWrap(from, to, toc)
	if e1 != nil {
		logger.Errorln("Unable to Hook : " + e1.Error())
	} else if h == nil {
		logger.Errorln("Unable to Hook nil hookingo result")
		e1 = errors.New("hookingo failure")
	} else {
		s := k.K2setMap(from, to, toc)
		logger.Debugln("Applying Hook:", s, " ", from)
	}
	return e1
}

// --------------------------------------------------------------------------
// Func HookWrapInterface - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func (k K2secureimpl) HookWrapInterface(from, to, toc interface{}) error {
	h, e1 := hookingo.ApplyWrapInterface(from, to, toc)
	if e1 != nil {
		logger.Errorln("Unable to Hook :" + e1.Error())
	} else if h == nil {
		logger.Errorln("Unable to Hook nil hookingo result")
		e1 = errors.New("hookingo failure")
	} else {
		s := k.K2setMap(from, to, toc)
		logger.Debugln("Applying Hook:", s, " ", from)
	}
	return e1
}

// --------------------------------------------------------------------------
// Func HookWrapInterface - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func (k K2secureimpl) HookWrapRaw(from uintptr, to, toc interface{}) error {
	h, e1 := hookingo.ApplyWrapRaw(from, to, toc)
	if e1 != nil {
		logger.Errorln("Unable to Hook :" + e1.Error())
	} else if h == nil {
		logger.Errorln("Unable to Hook nil hookingo result")
		e1 = errors.New("hookingo failure")
	} else {
		s := k.K2setAddrMap(from, to, toc)
		logger.Debugln("Applying Hook:", s, " ", from)
	}
	return e1
}

func (k K2secureimpl) InitSyms() {
	binaryPath, err := os.Executable()
	if err != nil {
		binaryPath = os.Args[0]
	}
	fname := binaryPath
	s, err := hookingo.GetSymbols(fname)
	if err != nil || s == nil {
		logger.Infoln("No debug symbols Find: ", err, " Filename :", binaryPath)
	} else {
		symb = s
	}
	return
}

func ConvertPtrReceiver(s string) string {
	if strings.HasPrefix(s, "*") {
		i := strings.LastIndex(s, ".")
		if i < 0 {
			return s
		}
		j := strings.Index(s, ".")
		if j < 0 {
			return s
		}
		if i == j {
			return s
		}
		name := s[1:j] + ".(*" + s[j+1:i] + ")." + s[i+1:]
		return name
	} else {
		return s
	}
}

// --------------------------------------------------------------------------
// Func HookWrapInterface - hook and logging failures etc. boilerplate
// --------------------------------------------------------------------------
func (k K2secureimpl) HookWrapRawNamed(xstrfrom string, to, toc interface{}) (string, error) {
	strfrom := ConvertPtrReceiver(xstrfrom)
	name := strfrom
	noname := ""
	sa := make([]string, 0)
	sa = append(sa, strfrom)
	if symb == nil {
		logger.Errorln("Unable to add Hook symb table is empty")
		return "", errors.New("Unable to add Hook symb table is empty")
	}
	from, ok := symb[strfrom]
	if !ok {
		err := errors.New(strfrom)
		logger.Errorln("Unable to locate and Hook :" + err.Error())
		return noname, err
	}
	h, e1 := hookingo.ApplyWrapRaw(from, to, toc)
	if e1 != nil {
		logger.Errorln("Unable to Hook :" + e1.Error())
	} else if h == nil {
		logger.Errorln("Unable to Hook nil hookingo result")
		e1 = errors.New("hookingo failure")
	} else {
		s := k.K2setAddrMap(from, to, toc)
		logger.Debugln("Applying Hook:", s, " ", from)
	}
	return name, e1
}

var myname = "github.com/k2io/go-k2secure/v2/k2secure_impl.Void"

//go:noinline
func Void() {
	return
}
func getElfOff(strfrom []string, stab []elf.Symbol) (map[string]uintptr, error) {
	elfOff := make(map[string]uintptr, 0)
	for _, k := range stab {
		if k.Name == myname {
			elfOff[myname] = uintptr(k.Value)
		} else {
			for _, s := range strfrom {
				if k.Name == s {
					elfOff[s] = uintptr(k.Value)
				}
			}
		}
	}
	return elfOff, nil
}
func getAddrFromElfOff(elfOff map[string]uintptr) (map[string]uintptr, error) {
	res := make(map[string]uintptr, 0)
	addrfound := false
	fptr := reflect.ValueOf(Void)
	ptr := uintptr(fptr.Pointer())
	off, ok := elfOff[myname]
	if !ok {
		return res, errors.New("cannot get address of base symbol")
	}
	for s, a := range elfOff {
		v := (ptr - off) + a
		vptr := unsafe.Pointer(v)
		sx := strcopy(s)
		res[sx] = uintptr(vptr)
		addrfound = true
	}
	if !addrfound {
		return res, errors.New("getAddrFromElfOff:no addresses found")
	}
	return res, nil
}
func strcopy(a string) string {
	var sx strings.Builder
	sx.WriteString(a)
	return sx.String()
}
