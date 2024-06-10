# GoPulzeTerminator

* Reproducing Spyboy technique, which involves terminating all EDR/XDR/AVs processes by abusing the zam64.sys driver
* Spyboy was selling the Terminator software at a price of $3,000 [for more detail](https://www.bleepingcomputer.com/news/security/terminator-antivirus-killer-is-a-vulnerable-windows-driver-in-disguise/)
* the sample is sourced from [loldrivers](https://www.loldrivers.io/drivers/49920621-75d5-40fc-98b0-44f8fa486dcc/)

# usage

* Place the driver `Terminator.sys` in the same path as the executable
* run the program as an administrator
* keep the program running to prevent the service from restarting the anti-malwares

![image](https://github.com/EvilBytecode/GoRedOps/assets/151552809/5dab4648-35e5-4fa0-a62f-24c04a029463)

  
# technical details

* The driver contains some protectiion mechanism that only allow trusted Process IDs to send IOCTLs, Without adding your process ID to the trusted list, you will receive an 'Access Denied' message every time. However, this can be easily bypassed by sending an IOCTL with our PID to be added to the trusted list, which will then permit us to control numerous critical IOCTLs

  ![image](https://github.com/ZeroMemoryEx/Terminator/assets/60795188/e26238c8-fcf8-40ec-9ed8-8e8de9436093)

* Comes with simple antidbg.
* Add This so WD Ignores defender by this quick sample

```go
exec.Command("powershell", "-Command", "Set-MpPreference -ExclusionExtension *.sys -Force").Run()
```
# How to lower detections?
- Use this repo to obfuscate the go code and lower detections: https://github.com/EvilBytecode/GolangObfuscator
- Credits to ZeroMemoryX 👍
