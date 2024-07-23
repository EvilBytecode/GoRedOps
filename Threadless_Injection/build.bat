@ECho off
gcc -shared -o threadless_injection_wrapper.dll threadless_injection_wrapper.c
dlltool --dllname threadless_injection_wrapper.dll --input-def threadless_injection_wrapper.def --output-lib threadless_injection_wrapper.lib
go build -o ThreadlessInject.exe
exit