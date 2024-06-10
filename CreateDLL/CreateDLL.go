package main

import "C"
import (
 "syscall"
 "golang.org/x/sys/windows"
)
// this will show message box that says it injected sucessfuly if injected sucessfully 
func init() {
 windows.MessageBox(windows.HWND(0), syscall.StringToUTF16Ptr("Injected Sucessfully"), syscall.StringToUTF16Ptr("Injection works"), windows.MB_OK)
}

func main() {}