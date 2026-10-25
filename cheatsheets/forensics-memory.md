# Memory forensics (Volatility 3)

Approved tools: `volatility3` (`vol` CLI), `volatility` 2 (`vol.py`), `dwarf2json`, OpenSSH-Session-Key-Recovery plugin, `strings`, `bulk_extractor`.

## Triage

```bash
file dump.raw                               # confirm it's a mem dump
vol -f dump.raw windows.info                # OS + build; detects profile automatically
```

For Linux dumps, build / download the symbol table first:
```bash
dwarf2json linux --elf /path/to/vmlinux-with-debug > linux-symbols.json
mv linux-symbols.json /opt/tools/volatility3/volatility3/symbols/linux/
vol -f dump.raw linux.bash
```

## Windows — the usual suspects

```bash
vol -f dump.raw windows.pstree              # process tree
vol -f dump.raw windows.pslist              # flat process list w/ PPID, create times
vol -f dump.raw windows.psscan              # unlinked processes (rootkit hiding)
vol -f dump.raw windows.cmdline             # command lines (reveals mimikatz, etc.)
vol -f dump.raw windows.dlllist             # loaded DLLs per process
vol -f dump.raw windows.netscan             # TCP/UDP connections
vol -f dump.raw windows.netstat             # same, legacy
vol -f dump.raw windows.handles             # file handles (shows locked flag files)
vol -f dump.raw windows.registry.hivelist   # loaded hives
vol -f dump.raw windows.hashdump            # NT hashes
vol -f dump.raw windows.lsadump             # LSA secrets
vol -f dump.raw windows.cachedump           # cached domain hashes
vol -f dump.raw windows.filescan            # scan memory for FILE_OBJECTs
vol -f dump.raw windows.dumpfiles --pid 1234
vol -f dump.raw windows.svcscan             # services (persistence)
```

## Linux

```bash
vol -f dump.raw linux.pstree
vol -f dump.raw linux.pslist
vol -f dump.raw linux.bash                  # bash history!!
vol -f dump.raw linux.psaux                 # arg dumps
vol -f dump.raw linux.lsmod                 # kernel modules
vol -f dump.raw linux.sockstat              # open sockets
```

## Credential / secret dumping

```bash
# Windows:
vol -f dump.raw windows.hashdump > nt.hashes
vol -f dump.raw windows.lsadump > lsa.secrets
# Then crack:
hashcat -m 1000 nt.hashes rockyou.txt       # NT hashes

# SSH session keys from a Linux dump:
vol -f dump.raw -p /opt/tools/OpenSSH-Session-Key-Recovery linux.ssh
# → session keys you can plug into Wireshark to decrypt the pcap

# pypykatz: parse an lsass dump directly
pypykatz lsa minidump lsass.dmp
```

## Finding flags

Flags often sit in these places:
```bash
# Shell history (both OSes)
vol -f dump.raw linux.bash | grep -i 'flag\|CSG\|CTF'
vol -f dump.raw windows.cmdline | grep -i flag

# Memory strings scan (brute force)
strings dump.raw | grep -iE 'flag\{|CSG\{|CTF\{' | sort -u | head
strings -el dump.raw | grep -iE 'flag\{'      # UTF-16LE strings (Windows)
strings -eb dump.raw | grep -iE 'flag\{'      # UTF-16BE

# bulk_extractor finds URLs, emails, credit cards, keys:
bulk_extractor -o out dump.raw
rg -i 'flag' out/
```

## Clipboard / recent files

```bash
vol -f dump.raw windows.registry.userassist   # recently run programs
vol -f dump.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
```

## Dump a specific process's memory

```bash
vol -f dump.raw windows.memmap --pid 1234 --dump
# → outputs pid.1234.dmp — then strings/grep for secrets
```

## Browser forensics (Chrome, Edge, Firefox)

Chrome/Edge store history/cookies as SQLite:
```bash
vol -f dump.raw windows.filescan | grep -i 'history\|cookies'
vol -f dump.raw windows.dumpfiles --virtaddr <addr>
sqlite3 History.sqlite 'SELECT url, title FROM urls'
```

Hindsight (pyhindsight) parses extracted Chrome profiles:
```bash
pyhindsight -i /path/to/Chrome/User\ Data/Default -o chrome.sqlite
```

## Common gotchas

- Volatility 3 auto-detects Windows profiles — no `--profile`. Vol2 does need `--profile`.
- Linux dumps NEED the matching symbol JSON — mismatch = cryptic errors.
- For memory dumps from VMs, use the matching DUMP format: raw, lime, elf, or vmware's `.vmem`.
- NT hash in `windows.hashdump` is MD4 of UTF-16LE password. Crack with `-m 1000`.

## Tips
- Always start with `windows.cmdline` or `linux.bash` — attackers' tooling is right there as plaintext.
- `strings -el` (little-endian UTF-16) catches Windows paths and passwords `strings` alone misses.
- If `windows.hashdump` is empty, the dump is pre-boot or SAM wasn't loaded; try `windows.cachedump` or carve registry hives via `windows.registry.hivelist` + `windows.dumpfiles`.
- Chainsaw + Hayabusa are for EVTX logs, not memory — don't confuse the workflow.
