package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"unsafe"
)

//https://github.com/LloydLabs/delete-self-poc/blob/main/main.c
//https://github.com/timwhitez/Doge-SelfDelete/blob/main/selfdel.go

var (
	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	rtlCopyMemory = kernel32.NewProc("RtlCopyMemory")
)

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info
type FILE_RENAME_INFO struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

func openHandle(path string) (error, windows.Handle) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err, 0
	}

	//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
	handle, err := windows.CreateFile(
		p,
		windows.DELETE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err, 0
	}
	return nil, handle
}

func renameHandle(handle windows.Handle) error {
	DS_STREAM_RENAME := ":test"
	var fRename FILE_RENAME_INFO

	lpwStream, err := windows.UTF16PtrFromString(DS_STREAM_RENAME)
	if err != nil {
		return err
	}
	fRename.FileNameLength = uint32(unsafe.Sizeof(lpwStream))

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
	_, _, err = rtlCopyMemory.Call(
		uintptr(unsafe.Pointer(&fRename.FileName)),
		uintptr(unsafe.Pointer(lpwStream)),
		unsafe.Sizeof(lpwStream),
	)
	if err.Error() != "The operation completed successfully." {
		return err
	}
	fmt.Println("[*] RtlCopyMemory ok")

	//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
	err = windows.SetFileInformationByHandle(
		handle,
		windows.FileRenameInfo,
		(*byte)(unsafe.Pointer(&fRename)),
		uint32(unsafe.Sizeof(fRename)+unsafe.Sizeof(lpwStream)),
	)
	if err != nil {
		return err
	}
	fmt.Println("[*] SetFileInformationByHandle ok")
	return nil
}

func depositeHandle(handle windows.Handle) error {

	//https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info
	type FILE_DISPOSITION_INFO struct {
		DeleteFile uint32
	}
	fDelete := FILE_DISPOSITION_INFO{}
	fDelete.DeleteFile = 1

	//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
	err := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&fDelete)),
		uint32(unsafe.Sizeof(fDelete)),
	)
	if err != nil {
		return err
	}
	fmt.Println("[*] SetFileInformationByHandle ok")
	return nil
}
func main() {
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	err, handle := openHandle(ex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[*] Open file handler")
	fmt.Println("[*] Handle :", handle)

	err = renameHandle(handle)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[*] Rename file")
	err = windows.CloseHandle(handle)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[*] Close file handler")
	err, handle = openHandle(ex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[*] Open file handler")
	fmt.Println("[*] Handle :", handle)
	err = depositeHandle(handle)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[*] Deposite file handle")
	err = windows.CloseHandle(handle)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[*] Close file handler")
}
