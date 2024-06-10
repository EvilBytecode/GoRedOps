package main

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"

	"github.com/MmCopyMemory/gostyle/pkg/gostyle"
)
//https://github.com/baum1810/batchobfuscator
func deobfuscateBaum1810(con string) string {
	re := regexp.MustCompile(`%[^%]*%`)
	cc := re.ReplaceAllString(con, "")
	return cc
}
//https://github.com/moom825/batch-obfuscator-made-in-python
func deobfuscateMoom825(con string) string {
	bytes := con[8:]
	dc := string(bytes)
	return dc
}

func rf(fn string) (string, error) {
	content, err := ioutil.ReadFile(fn)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func wf(of string, cc string) error {
	err := ioutil.WriteFile(of, []byte(cc), 0644)
	if err != nil {
		return err
	}
	return nil
}

func MM() {
	exec.Command("cls").Run()
	gostyle.Init()
	ascii := `
	 /$$$$$$$              /$$               /$$             /$$$$$$$                      /$$        /$$$$$$                                           /$$                        
	| $$__  $$            | $$              | $$            | $$__  $$                    | $$       /$$__  $$                                         | $$                        
	| $$  \ $$  /$$$$$$  /$$$$$$    /$$$$$$$| $$$$$$$       | $$  \ $$  /$$$$$$   /$$$$$$ | $$$$$$$ | $$  \__//$$   /$$  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$ 
	| $$$$$$$  |____  $$|_  $$_/   /$$_____/| $$__  $$      | $$  /$$| $$_____/| $$  \ $$| $$  \ $$| $$_/   | $$  | $$|  $$$$$$$| $$        /$$$$$$$  | $$    | $$  \ $$| $$  \__/
	| $$__  $$  /$$$$$$$  | $$    | $$      | $$  \ $$      | $$| $$| $$      | $$  | $$| $$  | $$| $$     | $$  | $$ \____  $$| $$       /$$__  $$  | $$ /$$| $$  | $$| $$      
	| $$  \ $$ /$$__  $$  | $$ /$$| $$      | $$  | $$      | $$| $$| $$      | $$  | $$| $$  | $$| $$     | $$  | $$ /$$  \ $$| $$       |  $$$$$$/  | $$  $$|  $$$$$$/| $$      
	| $$$$$$$/|  $$$$$$$  |  $$$$/|  $$$$$$$| $$$$$$$/      |  $$$$$$/|  $$$$$$$|  $$$$$$/|  $$$$$$/| $$     |  $$$$$$/|  $$$$$$/|  $$$$$$$  \______/   |  $$$$$/|  $$$$$$/|__/      
	|_______/  \_______/   \___/   \_______/|_______/        \______/  \_______/ \______/  \______/ |__/      \______/  \______/  \_______/             \___/   \______/          
	`
	gostyle.Taperfade(ascii, gostyle.PURPLE_TO_BLUE)
	cool := `
	=============================================================================================================================================================================== 
	| > [NOTE] CODED BY EVILBYTECODE AKA GODFATHERCODEPULZE	
	| > [OPTION] CHOOSE OPTION BELOW.																							   
	=============================================================================================================================================================================== 
	| [1] FAMILY = BAUM1810 Deobfuscator
	| [2] FAMILY = Chineese Letters / CERTUTIL . MOOM825 . DEADCODE
	|
	=============================================================================================================================================================================== 
	`
	gostyle.Taperfade(cool, gostyle.PURPLE_TO_RED)

}

func ho(opt int) bool {
	var fn string
	fmt.Print("> Enter filename: ")
	fmt.Scanln(&fn)
	con, err := rf(fn)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return true
	}

	var cc string
	var of string

	switch opt {
	case 1:
		cc = deobfuscateBaum1810(con)
		of = "deobfuscated_baum1810.txt"
	case 2:
		cc = deobfuscateMoom825(con)
		of = "deobfuscated_moom825.txt"
	default:
		fmt.Println("Invalid option. Please try again.")
		return true
	}

	err = wf(of, cc)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return true
	}

	fmt.Printf("Deobfuscated content saved to %s\n", of)
	return true
}

func main() {
	for {
		MM()
		var opt int
		fmt.Print("> Enter your choice: ")
		fmt.Scanln(&opt)
		if !ho(opt) {
			break
		}
	}
}