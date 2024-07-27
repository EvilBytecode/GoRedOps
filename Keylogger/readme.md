# Keylogger in Go

This Go program is a simple keylogger that monitors keyboard input and logs it to a file. Below is an explanation of its components:

## How It Works

- **GetAsyncKeyState**: This function checks the state of a specified virtual key. It is used to detect key presses.
- **GetKeyboardState**: This function retrieves the status of all virtual keys. It is used to check the current state of the keyboard.
- **MapVirtualKeyW**: This function translates a virtual-key code into a scan code or character value. It is used to translate virtual key codes to Unicode.
- **ToUnicode**: This function translates the specified virtual-key code and keyboard state to the corresponding Unicode character or characters.

The program continuously loops to monitor key presses and writes the corresponding Unicode characters to a log file located at `C:\temp\keylogger.txt`.

## Usage

To run the program, simply compile it using the Go compiler and execute the resulting binary. The program will start monitoring keyboard input and logging it to the specified file.

```bash
go build main.go
.\main.exe
```

## Disclaimer

This program is intended for educational purposes only. It is meant to demonstrate how keyloggers work and how they can be implemented in Go. It should not be used for malicious purposes.

## License

This program is released under the Unlicense, which allows anyone to use, modify, and distribute the code freely, without restrictions.
