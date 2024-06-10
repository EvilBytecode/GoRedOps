## Create DLL in Go
- Compile below to create an dll in go
```go -o main.dll -buildmode=c-shared main.go```
- this will create a new dll in your current directory, but note you need injector so i have taken care of that, and its in repo called GoDLLInjector