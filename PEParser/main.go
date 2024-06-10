package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"unsafe"
	"os"
)

const (
	IMAGE_DOS_SIGNATURE                     = 0x5A4D
	IMAGE_NT_SIGNATURE                      = 0x00004550
	IMAGE_NT_OPTIONAL_HDR32_MAGIC           = 0x10B
	IMAGE_NT_OPTIONAL_HDR64_MAGIC           = 0x20B
	IMAGE_FILE_MACHINE_I386                 = 0x14c
	IMAGE_FILE_MACHINE_AMD64                = 0x8664
	IMAGE_SCN_MEM_EXECUTE                   = 0x20000000
	IMAGE_SCN_MEM_READ                      = 0x40000000
	IMAGE_SCN_MEM_WRITE                     = 0x80000000
	IMAGE_DIRECTORY_ENTRY_EXPORT            = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT            = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE          = 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION         = 3
	IMAGE_DIRECTORY_ENTRY_SECURITY          = 4
	IMAGE_DIRECTORY_ENTRY_BASERELOC         = 5
	IMAGE_DIRECTORY_ENTRY_DEBUG             = 6
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      = 7
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR         = 8
	IMAGE_DIRECTORY_ENTRY_TLS               = 9
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       = 10
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      = 11
	IMAGE_DIRECTORY_ENTRY_IAT               = 12
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      = 13
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    = 14
	IMAGE_SIZEOF_SHORT_NAME                 = 8
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES        = 16
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_NT_HEADERS32 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                      uint16
	MajorLinkerVersion         uint8
	MinorLinkerVersion         uint8
	SizeOfCode                 uint32
	SizeOfInitializedData      uint32
	SizeOfUninitializedData    uint32
	AddressOfEntryPoint        uint32
	BaseOfCode                 uint32
	BaseOfData                 uint32
	ImageBase                  uint32
	SectionAlignment           uint32
	FileAlignment              uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion          uint16
	MinorImageVersion          uint16
	MajorSubsystemVersion      uint16
	MinorSubsystemVersion      uint16
	Win32VersionValue          uint32
	SizeOfImage                uint32
	SizeOfHeaders              uint32
	CheckSum                   uint32
	Subsystem                  uint16
	DllCharacteristics         uint16
	SizeOfStackReserve         uint32
	SizeOfStackCommit          uint32
	SizeOfHeapReserve          uint32
	SizeOfHeapCommit           uint32
	LoaderFlags                uint32
	NumberOfRvaAndSizes        uint32
	DataDirectory              [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                      uint16
	MajorLinkerVersion         uint8
	MinorLinkerVersion         uint8
	SizeOfCode                 uint32
	SizeOfInitializedData      uint32
	SizeOfUninitializedData    uint32
	AddressOfEntryPoint        uint32
	BaseOfCode                 uint32
	ImageBase                  uint64
	SectionAlignment           uint32
	FileAlignment              uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion          uint16
	MinorImageVersion          uint16
	MajorSubsystemVersion      uint16
	MinorSubsystemVersion      uint16
	Win32VersionValue          uint32
	SizeOfImage                uint32
	SizeOfHeaders              uint32
	CheckSum                   uint32
	Subsystem                  uint16
	DllCharacteristics         uint16
	SizeOfStackReserve         uint64
	SizeOfStackCommit          uint64
	SizeOfHeapReserve          uint64
	SizeOfHeapCommit           uint64
	LoaderFlags                uint32
	NumberOfRvaAndSizes        uint32
	DataDirectory              [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_SECTION_HEADER struct {
	Name                 [IMAGE_SIZEOF_SHORT_NAME]byte
	Misc                 [4]byte
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("Usage: ", args[0], " yourfile.exe")
		return
	}
	pe := args[1]

	data, err := ioutil.ReadFile(pe)
	if err != nil {
		panic(err)
	}

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&data[0]))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		panic("[!] Invalid IMAGE_DOS_SIGNATURE")
	}

	ntHeaderOffset := int(dosHeader.E_lfanew)
	if ntHeaderOffset+binary.Size(IMAGE_NT_HEADERS64{}) > len(data) {
		panic("[!] Invalid PE file")
	}

	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&data[ntHeaderOffset]))
	if ntHeader.Signature != IMAGE_NT_SIGNATURE {
		panic("[!] Invalid NT SIGNATURE")
	}

	fmt.Println("==================== FILE HEADER ==========================")
	fmt.Printf("[+] (FILE_HEADER) Arch: %s\n", func() string {
		if ntHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_I386 {
			return "x32"
		}
		return "x64"
	}())
	fmt.Printf("[+] Number of sections: %d\n", ntHeader.FileHeader.NumberOfSections)
	fmt.Printf("[+] Size Optional Header: %d\n\n", ntHeader.FileHeader.SizeOfOptionalHeader)

	fmt.Println("==================== OPTIONAL HEADER ======================")
	fmt.Printf("[+] (OPTIONAL_HEADER) Arch: %s\n", func() string {
		if ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
			return "x32"
		}
		return "x64"
	}())
	fmt.Printf("[+] Section Size code: %d\n", ntHeader.OptionalHeader.SizeOfCode)
	fmt.Printf("[+] File Checksum: %d\n", ntHeader.OptionalHeader.CheckSum)
	fmt.Printf("[+] Required Version: %d.%d\n", ntHeader.OptionalHeader.MajorOperatingSystemVersion, ntHeader.OptionalHeader.MinorOperatingSystemVersion)
	fmt.Printf("[+] Number of entries in the DataDirectory: %d\n\n", ntHeader.OptionalHeader.NumberOfRvaAndSizes)

	fmt.Println("==================== DIRECTORIES ==========================")
	fmt.Printf("[+] EXPORT DIRECTORY WITH SIZE: %d | RVA: 0x%X\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	fmt.Printf("[+] IMPORT DIRECTORY WITH SIZE: %d | RVA: 0x%X\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	fmt.Printf("[+] RESOURCE DIRECTORY WITH SIZE: %d | RVA: 0x%X\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
	fmt.Printf("[+] EXCEPTION DIRECTORY WITH SIZE: %d | RVA: 0x%X\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress)
	fmt.Printf("[+] BASE RELOCATION TABLE WITH SIZE: %d | RVA: 0x%X\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	fmt.Printf("[+] TLS DIRECTORY WITH SIZE: %d | RVA: 0x%X\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
	fmt.Printf("[+] IMPORT ADDRESS TABLE WITH SIZE: %d | RVA: 0x%X\n\n", ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress)

	fmt.Println("==================== SECTIONS =============================")

	sectionHeaderOffset := ntHeaderOffset + binary.Size(IMAGE_NT_HEADERS64{})
	for i := 0; i < int(ntHeader.FileHeader.NumberOfSections); i++ {
		sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&data[sectionHeaderOffset]))

		fmt.Printf("[#] %s\n", sectionHeader.Name[:])
		fmt.Printf("\tSize: %d\n", sectionHeader.SizeOfRawData)
		fmt.Printf("\tRVA: 0x%X\n", sectionHeader.VirtualAddress)
		fmt.Printf("\tRelocations: %d\n", sectionHeader.NumberOfRelocations)
		fmt.Printf("\tAddress: 0x%X\n", uintptr(unsafe.Pointer(sectionHeader))+uintptr(sectionHeader.VirtualAddress))
		fmt.Printf("\tPermissions:\n")

		if sectionHeader.Characteristics&IMAGE_SCN_MEM_READ != 0 {
			fmt.Println("\t\tPAGE_READONLY")
		}
		if sectionHeader.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			fmt.Println("\t\tPAGE_READWRITE")
		}
		if sectionHeader.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			fmt.Println("\t\tPAGE_EXECUTE")
		}
		if sectionHeader.Characteristics&(IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ) != 0 {
			fmt.Println("\t\tPAGE_EXECUTE_READWRITE")
		}

		sectionHeaderOffset += binary.Size(IMAGE_SECTION_HEADER{})
	}

	return
}
