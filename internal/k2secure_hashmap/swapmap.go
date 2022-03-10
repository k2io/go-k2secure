package hashmap

import (
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	mapInUse          *HashMap
	primaryMap        = &HashMap{}
	secondaryMap      = &HashMap{}
	mapInUseFlag      uintptr // flag that marks 0 for primary and 1 for secondary
	lastSwapTimestamp time.Time
	swapDuration      = time.Duration(300) * time.Second //600:5 minutes
)

func ifSwapNeeded() bool { // on every request
	currentTimestamp := time.Now()
	if currentTimestamp.Sub(lastSwapTimestamp) < swapDuration {
		return false
	}
	// fmt.Println("now is the time to swap")
	lastSwapTimestamp = currentTimestamp
	return true
}

func swapMaps() {
	// fmt.Println("inside swapMaps")
	if atomic.LoadUintptr(&mapInUseFlag) == 0 { // this means primary map is in use, and we are about to use secondary map
		// before using secondary map, lets clean it, in use is primary so cleaning secondary doesnt matter
		// fmt.Println("swapping primary to secondary")
		// fmt.Println(unsafe.Pointer(secondaryMap))
		secondaryMap = clearMap(secondaryMap)
		// fmt.Println(unsafe.Pointer(secondaryMap))
		// fmt.Println((*unsafe.Pointer)(unsafe.Pointer(&mapInUse)))
		// fmt.Println(unsafe.Pointer(primaryMap))
		// fmt.Println(unsafe.Pointer(secondaryMap))
		atomic.CompareAndSwapPointer((*unsafe.Pointer)(unsafe.Pointer(&mapInUse)), unsafe.Pointer(primaryMap), unsafe.Pointer(secondaryMap))
		// fmt.Println("the swap was successful : ", ok)
		atomic.CompareAndSwapUintptr(&mapInUseFlag, uintptr(0), uintptr(1)) // set new value as one to indicate secondary map is in use
		// fmt.Println("the swap of integer was successful : ", ok1)
		// fmt.Println((*unsafe.Pointer)(unsafe.Pointer(&mapInUse)))
		// fmt.Println(unsafe.Pointer(primaryMap))
		// fmt.Println(unsafe.Pointer(secondaryMap))
		// fmt.Println("swapping primary to secondary DONE")
	} else {
		// fmt.Println("swapping secondary to primary")
		primaryMap = clearMap(primaryMap)
		atomic.CompareAndSwapPointer((*unsafe.Pointer)(unsafe.Pointer(&mapInUse)), unsafe.Pointer(secondaryMap), unsafe.Pointer(primaryMap))
		atomic.CompareAndSwapUintptr(&mapInUseFlag, uintptr(1), uintptr(0)) // set new value as 0 to indicate primary map is in use
		// fmt.Println("swapping secondary to primary DONE")
	}
	// fmt.Println("exiting swapMaps")
}

func InitSwapMap() {
	mapInUse = primaryMap
	mapInUseFlag = 0
	lastSwapTimestamp = time.Now()
}

func clearMap(mapToClear *HashMap) *HashMap {
	// clean the map which we are going to use now
	return &HashMap{}
}

func InsertIntoMap(key string, value interface{}) {
	if ifSwapNeeded() {
		// fmt.Println("Now swapping the maps")
		swapMaps()
	}
	mapInUse.Set(key, value)
	// fmt.Println("Length of primary map : ", primaryMap.Len(), " Length of secondary map : ", secondaryMap.Len())
}

func GetFromMap(key string) (value interface{}) {
	val, _ := mapInUse.GetStringKey(key)
	if val == nil {
		// fmt.Println("GET : value NOT found in map, looking into other one")
		if atomic.LoadUintptr(&mapInUseFlag) == 0 { // this means mapInUse was primary map, so look for secondary map
			val, _ = secondaryMap.GetStringKey(key)
		} else {
			val, _ = primaryMap.GetStringKey(key)
		}
		if val != nil {
			// fmt.Println("GET : value found in OTHER map")
		}
	} else {
		// fmt.Println("GET : value found in CURRENT map")
	}
	return val
}

func Len() (int, int, int) {
	return mapInUse.Len(), primaryMap.Len(), secondaryMap.Len()
}

// see main function for instructions on how to use
// func main() {
// 	InitSwapMap()
// 	// on request received
// 	x := 0
// 	for true {
// 		InsertIntoMap(strconv.Itoa(x), "anmol jain")
// 		x++
// 		GetFromMap(strconv.Itoa(x - 1))
// 		// fmt.Println("Fetched key : ", x, " value : ", value)
// 	}
// }
