// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_ws

import (
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	"github.com/shettyh/threadpool"
)

// ---------------------------------------------------------------------------
// Func: fuzz - requested launch
// ---------------------------------------------------------------------------

var fuzzThreadPool *threadpool.ThreadPool = nil
var fuzzNoOfWorkers = 10
var fuzzQueueSize int64 = 100000
var FuzzClient K2SecureFuzz
var FuzzGrpcClient K2SecureFuzz

type FuzzTask struct {
	CcStruct k2models.K2ControlComand
	FStruct  k2models.Fuzz_struct
}

type K2SecureFuzz interface {
	K2Fuzz(*FuzzTask)
}

func (fTask *FuzzTask) Run() {
	f := fTask.FStruct
	isGrpc := f.IsGRPC

	if isGrpc {
		if FuzzGrpcClient == nil {
			logger.Errorln("FuzzGrpcClient not initialised")
		} else {
			FuzzGrpcClient.K2Fuzz(fTask)
		}
	} else {
		if FuzzClient == nil {
			logger.Errorln("FuzzClient not initialised")
		} else {
			FuzzClient.K2Fuzz(fTask)
		}
	}
}

func initFuzzThreadPool() {
	fuzzThreadPool = threadpool.NewThreadPool(fuzzNoOfWorkers, fuzzQueueSize)
	logger.Infoln("Fuzz thread pool initialised")
}

func submitFuzzTask(kcc k2models.K2ControlComand, kcc11 k2models.Fuzz_struct) {
	task := &FuzzTask{CcStruct: kcc, FStruct: kcc11}
	err := fuzzThreadPool.Execute(task)
	if err == nil {
		logger.Infoln("Task submitted successfully : ", kcc11)
	} else {
		logger.Errorln("Task submitted failure dropping : ", kcc11, err.Error())
	}
}
