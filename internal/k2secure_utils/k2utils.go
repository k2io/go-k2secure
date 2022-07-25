// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_utils

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/build"
	"io"
	"math"
	"strconv"
	"strings"

	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	k2model "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	"gopkg.in/yaml.v2"
)

// ---------------------------------------------------
// Basic Utils
// ---------------------------------------------------

func FindIpAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func GetUniqueUUID() string {
	uuid, _ := uuid.NewRandom()
	return uuid.String()
}

// ---------------------------------------------------
// Func: CalculateSha256 - compure sha256
// ---------------------------------------------------
func CalculateSha256(f string) string {
	b, e := ioutil.ReadFile(f)
	if e != nil {
		return "ERROR"
	}
	sum := sha256.Sum256(b)
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

// ---------------------------------------------------
// Func: CalculateSha256 - compure sha256
// ---------------------------------------------------

func IsFileExist(file string) bool {
	if _, err := os.Stat(file); err == nil {
		return true
	} else {
		return false
	}
}

// ---------------------------------------------------
// Func validJSON - basic check format matches JSON
// ---------------------------------------------------
func ValidJSON(j string) bool {
	var checkJ map[string]interface{}
	if err := json.Unmarshal([]byte(j), &checkJ); err != nil {
		return false
	}
	return true
}

func GetWorkingDir() string {
	w, _ := filepath.Abs(".")
	if w, e1 := os.Getwd(); e1 != nil {
		w, _ := filepath.Abs(w)
		if wi, e := os.Lstat(w); (e == nil) && (wi.Mode()&os.ModeSymlink != 0) {
			if wx, e2 := os.Readlink(w); e2 != nil {
				w, _ = filepath.Abs(wx)
			}
		}
	}
	w, _ = filepath.Abs(w)
	return w
}
func GetGoPath() string {
	path := os.Getenv("GOPATH")
	if path == "" {
		path = build.Default.GOPATH
	}
	return path
}
func GetGoRoot() string {
	path := os.Getenv("GOROOT")
	if path == "" {
		path = build.Default.GOPATH
	}
	return path
}

func ReadNodeLevelConfig(filePath string, conf *k2model.NodeLevelConfig) error {
	data, err := ioutil.ReadFile(filePath)
	if err == nil {
		if err == nil {
			err = yaml.Unmarshal(data, conf)
		}
	}
	return err
}

func ReadAppLevelConfig(filePath string, conf *k2model.AppLevelConfig) error {
	data, err := ioutil.ReadFile(filePath)
	if err == nil {
		if err == nil {
			err = yaml.Unmarshal(data, conf)
		}
	}
	return err
}

func CalculateFileSize(path string) string {
	fi, k2e2 := os.Stat(path)
	if k2e2 != nil {
		return "-1"
	} else {
		return getSize(fi.Size())
	}
}

func StructToString(data interface{}) string {
	json, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(json)
}

func getSize(size int64) string {
	var suffixes [8]string
	suffixes[0] = "B"
	suffixes[1] = "KB"
	suffixes[2] = "MB"
	suffixes[3] = "GB"
	suffixes[4] = "TB"
	suffixes[5] = "PB"
	suffixes[6] = "EB"
	suffixes[7] = "ZB"
	size1 := (float64)(size)
	base := math.Log(size1) / math.Log(1024)
	getSize := round(math.Pow(1024, base-math.Floor(base)), .5, 2)
	index := int(math.Floor(base))
	if index > 7 {
		index = 7
	}
	getSuffix := suffixes[index]
	return strconv.FormatFloat(getSize, 'f', -1, 64) + " " + string(getSuffix)
}

func round(val float64, roundOn float64, places int) (newVal float64) {
	var round float64
	pow := math.Pow(10, float64(places))
	digit := pow * val
	_, div := math.Modf(digit)
	if div >= roundOn {
		round = math.Ceil(digit)
	} else {
		round = math.Floor(digit)
	}
	newVal = round / pow
	return
}

func Untar(sourcefile, target string) error {

	file, err := os.Open(sourcefile)
	if err != nil {
		return err
	}
	defer file.Close()

	var fileReader io.ReadCloser = file
	if strings.HasSuffix(sourcefile, ".gz") {
		if fileReader, err = gzip.NewReader(file); err != nil {

			return err
		}
		defer fileReader.Close()
	}

	tarBallReader := tar.NewReader(fileReader)
	link := make(map[string]string)
	for {
		header, err := tarBallReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		filename := filepath.Join(target, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(filename, os.FileMode(header.Mode))

			if err != nil {
				return err
			}

		case tar.TypeReg:
			//	fmt.Println(filename)
			writer, err := os.Create(filename)

			if err != nil {
				return err
			}

			io.Copy(writer, tarBallReader)

			err = os.Chmod(filename, os.FileMode(header.Mode))

			if err != nil {
				return err
			}
			writer.Close()
		case tar.TypeSymlink:
			link[filename] = header.Linkname
		default:
			fmt.Println("Unable to untar type : %c in file %s", header.Typeflag, filename)
		}

	}
	for filename, linkname := range link {
		//fmt.Println(linkname, filename)
		os.Symlink(linkname, filename)
	}
	return nil
}
