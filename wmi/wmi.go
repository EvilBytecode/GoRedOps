package main

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"log"
)

// https://stackoverflow.com/questions/20365286/query-wmi-from-go
func main() {
	err := ole.CoInitialize(0)
	if err != nil {
		log.Fatal("Error while initialize ole: ", err)
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		log.Fatal("Error while CreatObject: ", err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		log.Fatal("Error while QueryInterface: ", err)
	}
	defer wmi.Release()

	// service is a SWbemServices
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", nil, "root/SecurityCenter2")
	if err != nil {
		log.Fatal("Error while CallMethod: ", err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// result is a SWBemObjectSet
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", "SELECT * FROM AntiVirusProduct")
	if err != nil {
		log.Fatal("Error while CallMethod: ", err)
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	countVar, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		log.Fatal("Error while GetProperty: ", err)
	}
	count := int(countVar.Val)

	var itemRaw *ole.VARIANT
	var asString *ole.VARIANT
	for i := 0; i < count; i++ {
		itemRaw, err = oleutil.CallMethod(result, "ItemIndex", i)
		if err != nil {
			log.Fatal("Error while CallMethod: ", err)
		}
		item := itemRaw.ToIDispatch()
		asString, err = oleutil.GetProperty(item, "displayName")
		if err != nil {
			log.Fatal("Error while CallMethod: ", err)
		}
		fmt.Println(asString.ToString())
	}

}
