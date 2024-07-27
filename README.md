# GoRedOps
<a href="https://t.me/pulzetools"><img src="https://img.shields.io/badge/Join%20my%20Telegram%20group-2CA5E0?style=for-the-badge&logo=telegram&labelColor=db44ad&color=5e2775"></a>

![GoRedOps Logo](GoRedOps.png)

GoRedOps is a collection of Golang projects designed specifically for red teamers and offensive security operations. This repository provides various tools and techniques essential for penetration testing, exploitation, and security research.

## Table of Contents

- [About](#about)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Contributing](#contributing)

## Project Structure

GoRedOps contains the following codes:

- **AntiDebugNOPACKAGE**
  - Anti-debugging techniques without packaging.
- **AntiDebugPackage**
  - Packaged anti-debugging techniques.
- **BatchfileDeobfuscator**
  - Tools for deobfuscating batch files.
- **CreateDLL**
  - Tools for creating dynamic-link libraries (DLLs).
- **crypto**
  - Various cryptographic algorithms (AES, ChaCha20, RC4, XOR).
- **EDR-XDR-AV-Killer**
  - Tools for evading and disabling EDR, XDR, and antivirus software.
- **ETWBypass**
  - Techniques for bypassing Event Tracing for Windows (ETW).
- **GoDLLInjector**
  - DLL injection techniques.
- **GoObfuscator**
  - Tools for obfuscating Go code.
- **injection_native_apc**
  - Native APC injection techniques.
- **injection_thread**
  - Thread injection techniques:
    - createThread
    - ntCreateThreadEx
- **instrumentation_callback**
  - Techniques involving instrumentation callbacks.
- **LifetimeAMSIBypass**
  - Bypassing AMSI (Antimalware Scan Interface).
- **misc**
  - Miscellaneous scripts and tools.
- **network**
  - Networking tools:
    - http (HTTP client and server)
    - pipes (Named pipes client and server)
    - tcp (TCP client and server)
- **ParentPIDSpoofing**
  - Techniques for spoofing parent process IDs.
- **PEParser**
  - Tools for parsing PE (Portable Executable) files.
- **process_dump**
  - Tools for dumping process memory.
- **ProtecProc**
  - Process protection techniques.
- **ProtectProcess**
  - Additional process protection techniques.
- **sandbox**
  - Techniques for detecting and evading sandboxes.
- **self_remove**
  - Tools for self-removing malware.
- **srdi**
  - Tools for shellcode reflection and dynamic invocation.
- **token**
  - Token manipulation tools:
    - impersonate
    - list
- **wmi**
  - Tools for interacting with Windows Management Instrumentation (WMI).
- **APC Injection**  
   - Exploits the Asynchronous Procedure Call (APC) technique to execute malicious code within target processes.

- **Early Bird APC Injection**  
  - A variation of APC Injection focusing on executing code before the main process starts.

- **Local Mapping Injection**  
  - Demonstrates malicious code injection via memory mapping into local processes.

- **Local Payload Execution**  
  - Addresses the direct execution of malicious payloads in a system's local environment.

- **Payload Execution Fibers**  
  - Demonstrates running shellcode using Fibers, a type of lightweight thread.

- **Payload Placement**  
  - Shows how to store shellcode in the .text section of a process and execute it.

- **Process Injection (Shellcode)**  
  - Exploits shellcode injection directly into running processes to control or execute malicious tasks.

- **Registry Shellcode**  
  - Demonstrates writing and reading shellcode to/from the Windows Registry.

- **Remote Function Stomping Injection**  
  - Exploits the substitution of functions in remote systems to carry out malicious activities.

- **Remote Mapping Injection**  
  - Demonstrates malicious code injection via memory mapping into remote processes.

- **Remote Thread Hijacking**  
  - Focuses on hijacking threads in remote system processes to execute malicious code.

- **Threadless Injection**  
  - Demonstrates threadless injection using Go & C, where shellcode is injected without creating a new thread.
- **RunPE (Run Portable Executable)**
  - Runs PE in Memory, PE = .exe.
- **Lifetime ETW - Amsi Bypass**
  - Patches Amsi and ETW forever in newly created powershell consoles.
## Getting Started

To get started with any of the tools in this repository, navigate to the respective project directory and follow the instructions in the `README.md` file provided.

### Prerequisites

- Go programming language installed (version 1.20+)
- Knowledge of Golang and offensive security operations, so have a brain in nutshell.

### Installation

Clone the repository, and Change Dir to your specified one:

```bash
git clone https://github.com/EvilBytecode/GoRedOps.git
cd GoRedOps
cd desired_folder
```


### Contributing
- We welcome contributions to improve GoRedOps. If you have an idea for a new tool or an enhancement to an existing one, please fork the repository and submit a pull request.
### How to contribute?
- Steps to Contribute
- Fork the repository.
- Create a new branch for your feature or bug fix.
- Implement your changes and commit them with descriptive messages.
- Push your changes to your fork.
- Submit a pull request to the main repository.

# License : 
- NoLicense (UnLicense)

# Credits:
- https://github.com/Enelg52/OffensiveGo (50%)
