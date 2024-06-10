package main


import (
	"unsafe"
	"syscall"
)


const (
	ProcessInstrumentationCallback = 40
)

type PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION struct {
	Version  uint32
	Reserved uint32
	Callback uintptr
}


func main() {
	NtSetInformationProcess := syscall.NewLazyDLL("ntdll").NewProc("NtSetInformationProcess")

	var InstrumentationCallbackInfo PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION

	InstrumentationCallbackInfo.Version  = 0x0
	InstrumentationCallbackInfo.Reserved = 0x0
	InstrumentationCallbackInfo.Callback = 0x0

	NtSetInformationProcess.Call( uintptr( 0xffffffffffffffff ),
				      ProcessInstrumentationCallback,
	  			      uintptr( unsafe.Pointer( &InstrumentationCallbackInfo ) ),
				      unsafe.Sizeof( InstrumentationCallbackInfo ) )
}
