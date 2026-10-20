# Reversing

Common tools: Ghidra, Cutter, radare2, gdb (+ GEF / peda / pwndbg),
x64dbg (Windows), dnSpyEx (.NET), jadx (Android), apktool, FLOSS, YARA, capa, angr,
Frida, ROPgadget, checksec, UPX, Detect It Easy, Impacket, mimikatz, pypykatz,
BinDiff, Bytecode Viewer.

## Triage

```bash
file target
checksec --file=target         # NX, PIE, canary, RELRO
strings -n 8 target | less
rabin2 -z target               # strings in .rodata only
rabin2 -I target               # bin info (arch, class, lang)
die target                     # Detect It Easy — packer / compiler guess
```

If `die` or `file` says it's packed → `upx -d target` first. If UPX refuses,
load into Ghidra and dump the unpacked region to disk.

## Static analysis

### Ghidra (primary)

```
Open target → Analyze with defaults → Window → Functions.
Decompiler pane (right): Ctrl+L to retype, L to rename.
Script Manager: GhidraScript examples under /Ghidra/Features/Base/ghidra_scripts.
```

Tips:
- Follow strings → references (`CTRL+SHIFT+F`) to find the function that uses them.
- `entry` isn't `main` on glibc — look for `__libc_start_main`'s first arg.
- Right-click → Set Equate for magic numbers / enums.

### radare2 / Cutter

```
r2 -A target               # analyze all
afl                        # list functions
pdf @ main                 # disasm main
VV                         # graph view
s sym.main; pdf            # seek + print
iE                         # exports
ii                         # imports
izz                        # all strings (incl. non-sections)
```

Cutter wraps r2 in a Qt GUI (AppImage at `/opt/tools/cutter.AppImage` on Kali).

### .NET (dnSpyEx)

Load the `.exe` or `.dll` → tree view shows classes → right-click → "Edit IL Instructions" or decompile to C#. For obfuscated .NET: try de4dot-cex if ever approved; otherwise rename symbols manually in dnSpy.

### JVM / Android

```bash
# Java JAR → source
java -jar fernflower.jar app.jar out_dir/
# or Bytecode Viewer (GUI)

# APK → source
apktool d app.apk           # resources + smali
jadx-gui app.apk            # decompiled Java
jadx app.apk -d out/        # CLI
dex2jar app.apk             # if you want JAR to open in dnSpyEx
```

### Python

```bash
# pyc → source
uncompyle6 file.pyc > file.py       # py 2.7 - 3.8
pycdc    file.pyc                   # py 3.9+ (decompyle++)
unpyc3   file.pyc                   # py 3.7-3.10

# PyInstaller single-file EXE → .pyc files
pyinstxtractor-ng target.exe
```

### Go

```bash
GoReSym -t -d -s target > symbols.txt   # recover stripped Go symbol table
```

Then re-open in Ghidra; symbol file can be loaded manually.

### Obfuscated strings

```bash
floss target --no-static-strings     # FLARE string decoder
capa  target                         # ATT&CK capabilities report
```

### YARA for family classification

```bash
yara -r rules/ target
```

## Dynamic analysis

### gdb (+ GEF / peda / pwndbg)

```bash
gdb target
# load GEF manually on Kali VM (not auto-sourced):
gdb -x /opt/tools/gef.py target
# peda is in /opt/tools/peda, sourced in ~/.gdbinit
```

Workflow:
```
b *0x401234         # break at address (also b main, b *&main)
r arg1 arg2
ni / si             # step over / into
x/32wx $rsp         # dump stack
info reg            # registers
vmmap               # memory map (gef)
telescope $rsp 32   # chain-walk (pwndbg/peda)
pattern create 200  # cyclic for buffer overflow offset
pattern search      # find offset after crash
```

### ltrace / strace

```bash
ltrace -f target        # library calls (follow forks)
strace -f -e trace=file target
strace -e trace=network target
```

Great for quickly spotting `strcmp`-based password checks.

### Frida

```bash
# hook a function at runtime
frida -l hook.js -f ./target --no-pause
```

```js
// hook.js — intercept strcmp and log args
Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
  onEnter(a) { console.log('strcmp', a[0].readCString(), '  vs  ', a[1].readCString()); }
});
```

### Windows debuggers

- **x64dbg** (portable zip, approved): standard Windows user-mode debugger. F2 breakpoint, F7 step-in, F8 step-over, F9 continue.
- **OllyDbg** (Wine on Kali): legacy, 32-bit targets.

## Common CTF tricks

### Bypass a `strcmp` password check

Static: find the comparison in Ghidra, read the plaintext string.
Dynamic: `ltrace ./target` → read the first arg of `strcmp`.

### Patch a jump

Ghidra: Patch Instruction → change `JNE` → `JE` or NOP out the branch → File → Export Program → Original File (raw bytes).

### Buffer overflow + ret2plt / ret2libc / ROP

```bash
checksec --file=target                   # inspect protections
ROPgadget --binary target | grep ': ret'
ROPgadget --binary libc.so.6 --only "pop|ret"
one_gadget libc.so.6                     # (not on approved list — compute manually)
```

Pattern:
```python
# use pwntools (via pip — stdlib pure-python crypto / sockets suffice )
from pwn import *
# or raw: sockets + struct.pack("<Q", addr) for 64-bit little-endian
```

### Format-string

Find a `printf` whose format argument is user-controlled. Leak with `%p %p %p` to walk the stack; write with `%n` + arg index.

### Shellcode

Assemble:
```bash
nasm -f elf64 shell.asm -o shell.o
objdump -d shell.o | awk '/^ /{for(i=2;i<=NF;i++) if($i~/^[0-9a-f][0-9a-f]$/) printf "\\x%s",$i}'
```

### Angr for symbolic execution

```python
import angr, claripy
p = angr.Project("./target", auto_load_libs=False)
inp = claripy.BVS("inp", 8*32)
state = p.factory.entry_state(args=["./target", inp])
sm = p.factory.simulation_manager(state)
sm.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
           avoid=lambda s: b"Wrong"   in s.posix.dumps(1))
if sm.found:
    print(sm.found[0].solver.eval(inp, cast_to=bytes))
```

## Credential dumping (for Windows IR / reversing crossovers)

```bash
# From a memory image or lsass dump
pypykatz lsa minidump lsass.dmp
# On a target VM (lab only)
mimikatz          # via Wine on Kali
```

Also check Impacket's `secretsdump.py`, `ntlmrelayx.py` etc. for AD challenges.

## Reference pointers on the Kali VM

```
/opt/tools/PayloadsAllTheThings     # ret2libc, format-string, shellcode notes
/opt/tools/HackTricks               # pwning techniques by platform
/opt/tools/GTFOBins.github.io       # LPE primitives for any binary name
/opt/tools/crypto-attacks           # paired with sagemath
```
