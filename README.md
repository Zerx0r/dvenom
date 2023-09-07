# 🐍 Double Venom (DVenom)

Double Venom (DVenom) is a tool that helps red teamers bypass AVs by providing an encryption wrapper and loader for your
shellcode.

## 🚀 Features

- 🛡️ Capable of bypassing some well-known antivirus (AVs).
- 🔒 Offers multiple encryption methods including RC4, AES256, XOR, and ROT.
- 🏗️ Produces source code in C#, Rust, PowerShell, ASPX, and VBA.
- 🔄 Employs different shellcode loading techniques: VirtualAlloc, Process Injection, NT Section Injection, Hollow
  Process Injection.

## 🎓 Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing
purposes.

### 👀 Prerequisites

- Golang installed.
- Basic understanding of shellcode operations.
- Familiarity with C#, Rust, PowerShell, ASPX, or VBA.

### ⬇️ Compilation

To clone and run this application, you'll need Git installed on your computer. From your command line:

```bash
# Clone this repository
$ git clone https://github.com/zerx0r/dvenom
# Go into the repository
$ cd dvenom
# Build the application
$ go build -o dvenom cmd/dvenom/main.go
```

## 🎮 Usage

After installation, you can run the tool using the following command:

```bash
./dvenom -h
```

### 🎛️ Command Line Arguments:

- -e: Specify the encryption type for the shellcode (Supported types: xor, rot, aes256, rc4).
- -key: Provide the encryption key.
- -l: Specify the language (Supported languages: cs, rs, ps1, aspx, vba).
- -m: Specify the method type (Supported types: valloc, pinject, hollow, ntinject).
- -procname: Provide the process name to be injected (default is "explorer").
- -scfile: Provide the path to the shellcode file.

### 📚 Example

To generate c# source code that contains encrypted shellcode.
> Note that if AES256 has been selected as an encryption method, the Initialization Vector (IV) will be auto-generated.

```bash
./dvenom -e aes256 -key secretKey -l cs -m ntinject -procname explorer -scfile /home/zerx0r/shellcode.bin > ntinject.cs
```

## 📋 Limitations

| Language   | Supported Methods                 | Supported Encryption  |
|------------|-----------------------------------|-----------------------|
| C#         | valloc, pinject, hollow, ntinject | xor, rot, aes256, rc4 |
| Rust       | pinject, hollow, ntinject         | xor, rot, rc4         |
| PowerShell | valloc, pinject                   | xor, rot              |
| ASPX       | valloc                            | xor, rot              |
| VBA        | valloc                            | xor, rot              |

## 💼 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## ⚠️ Disclaimer

Double Venom (DVenom) is intended for educational and ethical testing purposes only. Using DVenom for attacking targets
without prior mutual consent is illegal. The tool developer and contributor(s) are not responsible for any misuse of
this tool.
