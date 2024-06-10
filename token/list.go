package main

import (
	"fmt"
	"github.com/fourcorelabs/wintoken"
	"github.com/mitchellh/go-ps"
	"log"
)

/*
I'm not sure if I list all available correctly... But it work's :)
*/

func main() {
	priv := []string{"SeIncreaseQuotaPrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege"}
	token, err := wintoken.OpenProcessToken(0, wintoken.TokenPrimary) //pass 0 for own process
	if err != nil {
		log.Fatal("Error OpenProcessToken", err)
	}
	err = token.EnableTokenPrivileges(priv)
	if err != nil {
		log.Fatal("Error EnableTokenPrivileges", err)
	}
	processList, err := ps.Processes()
	if err != nil {
		log.Fatal("Error Get process list", err)
	}
	fmt.Printf("%-15s%-15s%-11s%-11s%-12s%-10s\n", "Domain", "Username", "TokenType", "LogonType", "ProcessId", "Process")
	fmt.Printf("%-15s%-15s%-11s%-11s%-12s%-10s\n", "------", "--------", "---------", "---------", "---------", "-------")
	var tokenType string
	for _, p := range processList {
		t, _ := wintoken.OpenProcessToken(p.Pid(), wintoken.TokenPrimary)
		tokenType = "Primary"
		if t != nil {
			u, _ := t.UserDetails()
			if u.Username != "" {
				fmt.Printf("%-15s%-15s%-11s%-11d%-12d%-12s\n", u.Domain, u.Username, tokenType, u.AccountType, p.Pid(), p.Executable())
			}
		}
	}
}
