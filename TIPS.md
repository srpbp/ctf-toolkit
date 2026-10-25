# Tips & tricks

Meta-advice beyond "which tool to run". Read before an event; re-skim when stuck.

## Before the event

- **Install everything beforehand.** `./install.sh` on the toolkit; `pip install pwntools cryptography pillow`; verify `check-approved` on the Kali VM.
- **Open the organizer PDF/wiki.** CTF rules often forbid specific tools or require specific flag formats (`CSG{...}`, `flag{...}`). Learn these before challenges go live.
- **Set up a notes dir per event.** One folder per challenge: raw files, your notes, output. Prevents the Downloads-folder archaeology spiral.
- **Pre-cache offline references.** On the Kali VM, confirm `/opt/tools/PayloadsAllTheThings`, `/opt/tools/HackTricks`, `/opt/tools/GTFOBins.github.io`, `/opt/tools/crypto-attacks`, `rockyou.txt`, SecLists are present.
- **Pre-generate a Flask SECRET_KEY wordlist** if the event has web challenges. Combine `rockyou.txt` + organizer-specific words.

## During a challenge — triage pattern

1. **Read the prompt. Twice.** The author tells you more than you think — challenge name, category, file extensions, hint sentences. 90% of challenges hint at the technique in the name.
2. **Look at what you were given.** File, URL, string, binary? Determine category and shape.
3. **Run the appropriate `*-triage` / `cve-scan` / `image-stego` first.** Fast way to see the whole surface.
4. **Try the obvious thing.** `strings file | grep flag` has solved real CTF challenges.
5. **Form a hypothesis.** Say it out loud / in notes: "this is Vigenère with a short key" / "there's an LFI in `?page=`". Hypotheses are testable.
6. **Test one thing at a time.** Change one variable per attempt — if 3 things change, you don't know which worked.
7. **Timebox.** 30 min stuck = switch challenges. Come back after another challenge clears your head.

## When truly stuck

- **Re-read the prompt.** Really.
- **Check the file name.** `line2plain_o65537.png` → "offset 65537". `vigenere_k7.txt` → key length 7. These are gifts.
- **Diff against a known-clean reference** if given (`plain.c` vs `challenge.c`).
- **Try the simplest possible interpretation first.** Submit what the image literally says. Many "easy" category challenges have the flag written in plain sight as a trick.
- **Grep across every output dir** `grep -R flag out/`.
- **Change layer.** Spent 20 min on crypto → try as encoding. Spent 20 min on stego → try as a cipher.
- **Walk away for 10 minutes.** Shower / walk / coffee. Insights land out of the shower, not the keyboard.
- **Ask teammates.** Even just explaining the problem helps.

## Flag format intuition

- Standard formats: `flag{...}`, `FLAG{...}`, `CSG{...}`, `csg2026{...}`, `TMCTF{...}`, `picoCTF{...}`, `HTB{...}`.
- Flags often look like `category_description` or `author_pun`. If you decrypt and see `password` or `hello`, your decrypt was probably right but the challenge wanted the surrounding `flag{...}` wrapper.
- When submitting, try both:
  - the raw text as-is
  - wrapped in the expected format (`flag{raw_text}`)
  - URL-safe / underscore replacements

## Common CTF-isms

| Pattern | What it means |
| --- | --- |
| File named `*_o<N>` | Offset N into the file |
| File named `*_k<N>` | Key length N |
| File named `cat*`, `fish*`, `dog*` | Picture of that animal — the picture IS the challenge |
| Challenge says "easy" | Usually genuinely easy; don't over-think |
| Challenge says "hard" | Multi-step chain; patience |
| "Hidden in plain sight" | Look at metadata, filenames, trailing bytes |
| "Follow the white rabbit" | Chain of hints — each decode leads to another |
| "RTFM" | The man page of a specific tool is the hint |

## Infrastructure tips

- **Keep a terminal multiplexer open.** tmux / screen so a disconnect doesn't kill a long-running scan.
- **Script everything you'd do twice.** The second time you type `curl -X POST -H 'ct:application/json' -d '{...}' $URL`, make it a `.sh`.
- **Version-control your writeups.** `git init` in your notes; `git add -A && git commit -m 'solved X'` after each win. Easy to export a repo at event end for a public write-up.
- **Record stdout for every big scan.** `script -c 'nmap -A ...' nmap.log`. Rare but priceless when you need to re-check what you saw an hour ago.

## Workflow with the toolkit

- `check-approved` → confirm environment on first login.
- `cipher-id --chain` → first move on anything that looks encoded.
- `image-stego` → first move on any image.
- `pcap-triage` → first move on any pcap.
- `cve-scan --source <dir>` → first move when given source code (whitebox).
- `stego-triage` → first move when the file type is unclear and might be stego.
- `cve-scan <url|ip>` → first move on a running network target.

## Common mistakes

- Trying Vigenère brute on short text (<60 chars). Chi-squared is noisy; use `vigenere-prefix` with the likely flag format instead.
- Trusting IC on short text. IC = 0.07 on 36 chars is almost random noise, not a key-length signal.
- Submitting the wrong wrapper (`CSG{...}` vs `flag{...}`). Always try the raw string and the organizer's format.
- Spending 40 minutes on blackbox when the challenge gave you source. Always check for whitebox materials first.
- Running `rockyou.txt` on a password that's clearly derived from the challenge name. Try the challenge-specific wordlist first.
- Forgetting case sensitivity in flags. Try both cases when submission fails.
- Guessing that the extracted string is encrypted when it's actually just scrambled English (anagram, columnar transposition, reversed).

## Reviewing a solve (do this after each flag)

- Note the technique in your notes (link to the relevant cheatsheet).
- If a scripted brute could have shortcut the manual steps, add a one-liner to your toolkit.
- If you learned a new op / recipe, add it to the right cheatsheet.
- Share the writeup — forces you to understand it fully.

## Team / coordination tips

- Keep a shared doc / board with: who's on what, blocked flags, hint budgets.
- Don't duplicate work. "I'm on crypto 3" > silence.
- Share hints and partial progress. One person's "I decoded this one blob to this garbage" is another person's "oh that's rail-fence 7".
- Submit flags from one person's device if the platform rate-limits per-user. Avoids racing.

## After the event

- Download writeups from other teams if public. Add techniques you didn't know to your cheatsheets.
- Diff your approach vs. intended solution. Were you solving the right problem?
- Rotate your toolkit:
  - Prune scripts you didn't use.
  - Add scripts for techniques you had to improvise.
  - Update `CHECKLIST.md` with new entries.
- Push your repo. Someone else solving a similar challenge next year will thank you.
