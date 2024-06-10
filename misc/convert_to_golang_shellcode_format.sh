#!/bin/bash
#
# Converts a Cobalt Strike shellcode from C format to Golang format, usage : > bash convert_to_golang_shellcode_format.sh payload.c
#
#

# take "payload.c" shellcode beacon 
beacon_file="$1"

beacon_file_contents=$(<"$beacon_file")

go_shellcode=$( echo "$beacon_file_contents" | sed 's/unsigned char buf\[\] = "\(.*\)"/buf = []byte{ \1 }/' )
go_shellcode=$( echo "$go_shellcode"         | sed 's/\\x\([0-9A-Fa-f][0-9A-Fa-f]\)/0x\1, /g' ) 

echo "$go_shellcode"

