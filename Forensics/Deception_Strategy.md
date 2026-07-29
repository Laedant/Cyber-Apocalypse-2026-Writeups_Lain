# Deception Strategy

────────────────────────────────────────────────────────────

## 1. CHALLENGE OVERVIEW
────────────────────────
**NAME:** Deception Strategy
**CATEGORY:** Forensics
**DIFFICULTY:** Easy
**PLATFORM:** HTB Cyber Apocalypse 2026

**DESCRIPTION:**
> *A trusted harbor-latch mechanism is behaving erratically, processing routine transit writs with a strange, stuttering cadence. Under the cover of this mechanical distraction, an unseen hand bypassed the inner witness-marks and completely drained an Eastreach private credit-cache. Sift through the compromised latch's residual ash-logs and custody chains to track the phantom access before the stolen coin vanishes into the undercity.*

In plain terms: a trusted application (Discord — the "harbor-latch") was behaving abnormally due to a sideloaded malicious module (the "mechanical distraction"). Under cover of that legitimate-looking process, an attacker bypassed integrity checks (the "witness-marks") and drained a crypto wallet (the "private credit-cache"). A compromised host's disk image, Process Monitor capture (`Logfile.PML`, the "ash-logs"), and network traffic (`network.pcap`, the "custody chains") were provided. The objective was to trace the infection chain end-to-end — from initial module load through C2 decryption — and recover the stolen seed phrase before it could be laundered ("vanish into the undercity").

────────────────────────────────────────────────────────────

## 2. INITIAL RECON / ENTRY POINT
───────────────────────────────
**STARTING POINT:**
- `Logfile.PML` — 674 MB Sysinternals Process Monitor capture
- `network.pcap` — packet capture, ~9.7 MB
- `C.zip` — full disk image of `C:\Users\admin\...`

**FIRST OBSERVATIONS:**
- `network.pcap` showed `POST /api/v9/experiments` requests to a host presenting itself as `discord-cdn.com`, but resolving to an IP outside Discord's real infrastructure — carrying large hex-encoded blobs.
- `Logfile.PML` is a proprietary binary format; raw `strings`/grep triage was unreliable and produced false positives.

**FIRST ACTIONS:**
- Installed `procmon-parser` (Python) to properly walk the PML's structured event records instead of byte-pattern guessing.
- Enumerated `Operation` types to find `Load_Image` (module load) events.
- Grouped `Load_Image` events by process name to spot anomalies — `rundll32.exe` hosting a DLL stood out immediately.

────────────────────────────────────────────────────────────

## 3. ANALYSIS / INVESTIGATION
────────────────────────────
**STATIC ANALYSIS:**
- Pulled the suspicious DLL out of the disk image: `C:\Users\admin\AppData\Local\Discord\app-1.0.9243\d3d11.dll`.
- `file`/`objdump` showed a UPX-packed PE32+ DLL — sparse `strings` output confirmed packing (section named `UPX0`).
- Unpacked with `upx -d d3d11.dll -o d3d11_unpacked.dll`.
- `pefile` showed a single export: `D3D11CreateDevice` — a proxy-export trick masquerading as the real Direct3D API.
- Wide-string (`strings -el`) scan of the unpacked binary revealed: `Local\DiscordRuntimeCache`, `SessionToken`, `discord-cdn.com`, `Discord/1.0`, and mangled symbols (`ReadSessionToken`, `WriteSessionToken`, `GenerateSessionToken`).

**DYNAMIC ANALYSIS:**
- Filtered PML `Load_Image` events for `d3d11.dll`: first loaded passively by `Discord.exe` (PID 7664) via DLL search-order sideloading, then explicitly invoked by `rundll32.exe` (PID 8152) with `D3D11CreateDevice`.
- Filtered PML `RegQueryValue` events by PID 7664: found a 16-byte `REG_BINARY` at `HKCU\Environment\SessionToken` — abnormal, since real `HKCU\Environment` values are always strings.
- Extracted the four `POST` payloads to `discord-cdn.com` from the pcap via `tshark -Y "http.request.method==POST && http.host==\"discord-cdn.com\"" -e http.file_data`.

**KEY FINDINGS:**
- Sideloading is used both to execute silently under a trusted process (`Discord.exe`) and to manually trigger the payload (`rundll32.exe`).
- The `SessionToken` registry value is the RC4 key material, but must be used **byte-reversed** to decrypt correctly (a mismatched-endianness deliberate anti-analysis touch — raw key produced garbage, reversed key produced clean plaintext).
- C2 exfil is disguised as Discord's own experiments API to blend into legitimate traffic.

**THOUGHT PROCESS:**
Each artifact confirmed the next: the mutex/registry/export strings only appeared after unpacking, which explained why initial raw-byte searches on the PML/pcap failed — the payload doesn't touch disk in plaintext form at any point, it's all packed or encrypted until runtime/decrypt.

────────────────────────────────────────────────────────────

## 4. VULNERABILITY IDENTIFICATION
───────────────────────────────
**ROOT CAUSE:**
DLL search-order hijacking (sideloading) — a malicious `d3d11.dll` placed inside Discord's own app directory is loaded automatically ahead of the legitimate system DLL.

**WHY IT WORKS:**
Windows' default DLL search order checks the application's own directory before `System32`. Discord's Electron/Chromium GPU init calls `LoadLibrary("d3d11.dll")`, unknowingly loading the attacker's copy instead.

**AFFECTED COMPONENT:**
`Discord.exe` (v1.0.9243) → `d3d11.dll` in its app folder.

**CHAIN:**
- 4.1 Primary: DLL sideload via search-order hijack (persistence/execution under a trusted, signed process)
- 4.2 Secondary: RC4-encrypted exfiltration over HTTP traffic masquerading as Discord's own API, using a registry-derived (reversed) key

────────────────────────────────────────────────────────────

## 5. EXPLOITATION METHOD
────────────────────────
**STRATEGY:**
Passive forensic reconstruction — no exploitation required; traced execution/registry/network artifacts to reverse the malware's own key-derivation and decrypt its exfil traffic.

**TOOLS USED:**
`procmon-parser` (Python), `pefile`, `upx`, `tshark`, `strings`, `objdump`, custom Python RC4 implementation.

**STEPS:**
1. Parsed PML for `Load_Image` events → identified `d3d11.dll` sideload by `Discord.exe`, then explicit invocation by `rundll32.exe`.
2. Extracted and unpacked the DLL (UPX) → recovered export table and Unicode strings (mutex name, C2 domain).
3. Parsed PML for `RegQueryValue` events by the malicious PIDs → recovered the 16-byte `SessionToken` value.
4. Extracted the four `POST /api/v9/experiments` bodies from the pcap via `tshark`.
5. Brute-forced simple key transforms (raw / MD5 / SHA1 / SHA256 / reversed) against RC4 decryption, scoring output by printable-ASCII ratio → **reversed raw bytes** was the correct key.
6. Decrypted all four payloads; three were decoy/filler content, the fourth was the stolen seed phrase.

**PAYLOADS / COMMANDS:**
```python
key = bytes.fromhex("1aa3a658ce2c4a4258983eba1853f08c")[::-1]

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i+1) % 256
        j = (j+S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i]+S[j]) % 256])
    return bytes(out)
```

**ITERATIONS:**
- Raw key → garbage output.
- MD5/SHA1/SHA256 of key → garbage output.
- Reversed raw key bytes → clean plaintext (confirmed via printable-ratio scoring across candidates).

────────────────────────────────────────────────────────────

## 6. FLAG RETRIEVAL
──────────────────
**FLAG (stolen seed phrase):**
```
glow fix connect talon title risk barrel marine truth disease garbage cheese
```

**LOCATION:**
Final `POST /api/v9/experiments` payload to the spoofed `discord-cdn.com` host in `network.pcap`, RC4-encrypted.

**EXTRACTION METHOD:**
`tshark` HTTP payload extraction → RC4 decryption using the reversed `HKCU\Environment\SessionToken` registry value as key.

────────────────────────────────────────────────────────────

## 7. ALTERNATIVE PATHS (OPTIONAL)
───────────────────────────────
- Could have found the DLL export/strings faster by checking for `UPX0`/`UPX1` section names immediately rather than exhausting raw `strings` first.
- Windows-native path: open `Logfile.PML` directly in Procmon GUI, filter `Operation is Load Image`, and inspect the Command Line / registry columns visually instead of scripting a parser.

────────────────────────────────────────────────────────────

## 8. KEY TAKEAWAYS
────────────────
**TECHNICAL LESSON:**
DLL search-order hijacking (T1574.001) combined with registry-based key storage and protocol-mimicking C2 (T1071.001) is a common, low-noise persistence + exfil combo.

**MENTAL MODEL:**
When strings analysis on a binary comes back suspiciously empty, check for packing before concluding there's nothing there. When a "standard" key doesn't decrypt cleanly, cheaply brute-force simple transforms (reverse, hash) before assuming the wrong key entirely.

**APPLICATION:**
Applies directly to real-world triage of trojanized legitimate applications (Discord, browsers, updaters) and to any CTF/forensics case involving encrypted C2 — always validate key material by testing decryption output's printable-text ratio rather than assuming byte order.

────────────────────────────────────────────────────────────

## Reference — Full Answer Key

| Question | Answer |
|---|---|
| Originating process | `Discord.exe` (PID 7664) |
| Module load timestamp | `1782570491` |
| Exported function invoked | `D3D11CreateDevice` |
| 16-byte registry value | `1AA3A658CE2C4A4258983EBA1853F08C` (`HKCU\Environment\SessionToken`) |
| Mutex name | `Local\DiscordRuntimeCache` |
| C2 server IP | `203.49.53.184` |
| Stolen seed phrase | `glow fix connect talon title risk barrel marine truth disease garbage cheese` |
