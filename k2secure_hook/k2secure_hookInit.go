// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	k2secure_ws "github.com/k2io/go-k2secure/v2/k2secure_ws"
)

var logger = logging.GetLogger("hook")

// --------------------------------------------------------------------------
// func init - initialize package, apply hooks
// --------------------------------------------------------------------------
func init() {
	if !k2i.K2OKhook() {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	logging.NewStage("3", "INSTRUMENTATION", "Applying instrumentation")
	parsePkg()
	locateImports()
	initSyms()
	init_hooks()

}

func initSyms() {

	k2i.InitSyms()

}

func init_hooks() {
	init_opt_hooks()
	if debug_drop_hooks {
		return
	}
	initServerHook()
	initSqlHook()
	initOshooks()
	initFilehooks()
	initTrackerhook()
	initBlacops()
	k2i.SetHooked()

}

func initBlacops() {
	k2secure_ws.FuzzClient = K2HttpFuzz{}
}

func parsePkg() {

	tset := token.NewFileSet()
	af, err := parser.ParseFile(tset, "", nil, parser.PackageClauseOnly)
	if err != nil {
		return
	}
	logger.Infoln("package found:" + af.Name.String())

}

// ----------------------------------------------------------------
// Func: locateImports
//    Check appropriate k2secure submodules are included.
// ----------------------------------------------------------------
func locateImports() {

	tset := token.NewFileSet()
	p := getAppPath()
	imap := make(map[string]bool, 0)
	k2map := make(map[string]bool, 0)
	i2kmap := make(map[string]string, 0)

	// --- mapping -- add for each new module intercepted --
	id := "github.com/k2io/go-k2secure"
	k2secure := "github.com/k2io/go-k2secure/v2"
	i2kmap["github.com/go-ldap/ldap/v3"] =
		id + "/k2secure/k2secure_ldapwrap/v2"
	i2kmap["github.com/mongo-driver/mongo"] =
		id + "/k2secure/k2secure_mongowrap/v2"
	i2kmap["github.com/robertkrimen/otto"] =
		id + "/k2secure/k2secure_ottowrap/v2"
	i2kmap["github.com/augustoroman/v8"] =
		id + "/k2secure/k2secure_v8wrap/v2"
	i2kmap["github.com/antchfx/xpath"] =
		id + "/k2secure/k2secure_xpathwrap/v2"
	i2kmap["github.com/antchfx/xmlquery"] =
		id + "/k2secure/k2secure_xmlquerywrap/v2"
	i2kmap["github.com/antchfx/jsonquery"] =
		id + "/k2secure/k2secure_jsonquerywrap/v2"
	i2kmap["github.com/antchfx/htmlquery"] =
		id + "/k2secure/k2secure_htmlquerywrap/v2"
	i2kmap["google.golang.org/grpc"] =
		id + "/k2secure/k2secure_grpcwrap/v2"

	// --- end mapping ---
	counter := false
	logger.Infoln("k2secure Imports Scanning")
	if e := filepath.Walk(p,
		func(px string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || fi.IsDir() || !strings.HasSuffix(px, ".go") {
				return nil
			}
			f, err := parser.ParseFile(tset, px, nil, parser.ImportsOnly)
			if err != nil {
				logger.Errorln("walk fail parse: %v %v", p, err.Error())
			} else {
				for _, sx := range f.Imports {
					counter = true
					s := sx.Path.Value
					s = s[1 : len(s)-1] //remove quotes
					logger.Info("import:" + s)
					k2path := id
					if strings.HasPrefix(s, k2path) {
						k2map[s] = true
					} else {
						imap[s] = true
					}
				}
			}
			return nil
		}); e != nil {
		logger.Errorln("failed to walk app path...%v %v", p, e.Error())
	}

	if !counter {
		logger.Warnln("No import founds, Assuming application imported all go-k2secure packages")
		return
	}
	if _, ok := k2map[k2secure]; ok == false {
		logger.Warnln("Needed to enable K2 protect - import:", id)
	} else {
		logger.Infoln("OK: K2 protect - imported:", id)
	}
	for k, _ := range imap {
		if s, ok := i2kmap[k]; ok == true {
			if _, ok2 := k2map[s]; ok2 == false {
				logging.PrintWarnlog("Suggested K2 protect imports :"+s+" for: "+k, "INSTRUMENTATION")
			} else {
				logger.Infoln("OK: import " + s + " protects " + k)
			}
		}
	}
}

// ----------------------------------------------------------------
// Func: getAppPath - find application path taking into account
//             invocation path e.g. ../xyz/path-to-app/app
// ----------------------------------------------------------------
func getAppPath() string {

	c, e := os.Getwd()
	if e == nil {
		return "./"
	}
	cprime := filepath.Dir(os.Args[0])
	s := filepath.Join(c, cprime)
	c, e = filepath.Abs(s)
	if e != nil {
		return s
	}
	return c
}
