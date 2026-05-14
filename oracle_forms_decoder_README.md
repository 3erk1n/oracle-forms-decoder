# Oracle Forms Decoder — Burp Suite Extension

**Author:** Berkin Deha  
**Extension Type:** Python (Jython 2.7)  
**Tested on:** Burp Suite Professional 2024.x / 2026.x  
**Target:** Oracle Forms 10g / 11g (HTTP Transport / lservlet)

---

## Overview

Oracle Forms HTTP Transport (FHT) encrypts all client–server communication with RC4 using a 5-byte session key derived during the initial handshake. This extension **automatically decrypts, parses, and optionally modifies** Oracle Forms traffic in real time — with no manual steps required.

It is the first and only Burp Suite extension specifically designed for Oracle Forms penetration testing.

---

## Features

| Feature | Detail |
|---|---|
| **Auto-decrypt** | Derives the RC4 key from the Pragma 1 GDay/Mate handshake; decrypts all subsequent Pragmas automatically |
| **FHT protocol parser** | Full binary parser for Oracle Forms FHT wire format; resolves 470+ property IDs (from `ID.class` / `Message.class`) |
| **Sensitive value highlighting** | Automatically flags `VALUE`, `LOGON_USERNAME_VALUE`, `LOGON_PASSWORD_VALUE` and other credential properties |
| **Oracle Forms tab** | Decoded messages appear in a dedicated "Oracle Forms" tab in Proxy History and Repeater — alongside Pretty/Raw/Hex |
| **In-tab editing** | Request-side content is editable; modified content is re-encoded (FHT binary) and re-encrypted (RC4) before sending |
| **OF Rules tab** | Standalone Burp tab for rule-based auto-modification: set `PROPERTY = value`, click Apply — every matching request is patched in transit with no interception required |
| **Continuous RC4 stream** | Correctly tracks the RC4 keystream state across all Pragmas (the stream is NOT reset per Pragma) |

---

## Technical Background

### Protocol

Oracle Forms communicates over HTTPS via a Java applet connecting to `/forms/lservlet`. Each HTTP POST carries a `Pragma: N` sequence header. The traffic flow is:

```
Pragma 0  GET   – servlet info (cleartext)
Pragma 1  POST  – GDay/Mate handshake (cleartext, contains key material)
Pragma 3  POST  – first encrypted request/response
Pragma 4+ POST  – encrypted, continuous RC4 stream
```

Note: Pragma 2 does not exist in the Oracle Forms protocol.

### RC4 Key Derivation

The 5-byte RC4 key is derived from random bytes exchanged in the Pragma 1 handshake (`GDay` magic in the request, `Mate` magic in the response). The derivation formula was reverse-engineered from `oracle/forms/net/HTTPConnection.class` bytecode inside `frmall.jar`:

```python
key[0] = (client_random >> 8)  & 0xFF
key[1] = (server_random >> 4)  & 0xFF
key[2] = 0xAE                          # constant
key[3] = (client_random >> 16) & 0xFF
key[4] = (server_random >> 12) & 0xFF
```

Both `client_random` and `server_random` are transmitted in **cleartext** in Pragma 1, making the key trivially recoverable by any proxy.

### Security Findings

1. RC4 with a 5-byte (40-bit) key — cryptographically broken, brute-forceable
2. `client_random` sourced from `java.util.Random.nextInt()` — predictable PRNG
3. Both random values transmitted in cleartext in Pragma 1
4. Continuous RC4 stream (not fresh per Pragma) — a single captured session exposes all plaintext
5. Credential fields (`LOGON_USERNAME_VALUE`, `LOGON_PASSWORD_VALUE`) visible to any proxy

---

## Installation

1. Download `jython-standalone-2.7.x.jar` from https://www.jython.org/download
2. In Burp: **Settings → Extensions → Python environment** → set the Jython JAR path
3. **Extensions → Add → Extension Type: Python** → select `oracle_forms_burp.py`
4. Output tab should show: `[OracleForms] Extension loaded. Waiting for Oracle Forms traffic...`

---

## Usage

### Viewing decoded traffic

1. Ensure Burp proxy is active **before** launching the Oracle Forms client
2. Open the Oracle Forms application — the extension captures the Pragma 1 handshake and derives the session key automatically
3. Click any `/forms/lservlet` POST in **Proxy History** → select the **Oracle Forms** tab
4. Decoded FHT messages are displayed with property names and values; sensitive fields are highlighted

### Modifying traffic (OF Rules tab)

1. Open the **OF Rules** tab in the Burp suite toolbar
2. Enter modification rules:
   ```
   # property name = replacement value
   LOGON_USERNAME_VALUE = testuser
   LOGON_PASSWORD_VALUE = testpass
   VALUE = injected_value
   ```
3. Click **Apply Rules**
4. Perform the action in Oracle Forms — every matching outgoing request is automatically decrypted, patched, re-encrypted, and forwarded without interception

### In-tab editing (Repeater)

1. Send any `/forms/lservlet` POST to Repeater
2. Select the **Oracle Forms** tab — the decoded content is editable
3. Modify any string value
4. Click **Apply & Forward** or send from Repeater — the body is re-encoded and re-encrypted automatically

---

## Supported Property IDs

The extension includes a full mapping of 470+ Oracle Forms property IDs extracted from `ID.class`. Highlighted sensitive properties:

| ID | Name |
|---|---|
| 131 | VALUE |
| 433 | LOGON_USERNAME_VALUE |
| 434 | LOGON_PASSWORD_VALUE |
| 435 | LOGON_DATABASE_VALUE |
| 439 | LOGON_OLDPASSWORD_VALUE |
| 440 | LOGON_NEWPASSWORD_VALUE |
| 444 | DISPERR_SQL_VALUE |
| 445 | DISPERR_ERROR_VALUE |

---

## Limitations

- Supports Oracle Forms 10g/11g HTTP Transport (lservlet). WebSocket transport is not covered.
- If any Pragma in a session is missing from the capture, subsequent Pragmas cannot be decrypted (continuous RC4 stream).
- When modifying a string that changes the body length, the RC4 stream position for subsequent Pragmas in the same session will shift. This is expected behaviour for single-request modification testing.
- Requires Jython 2.7 (Python 2 extension).

---

## Disclaimer

This extension is intended for **authorized security testing only**. Do not use against systems without explicit written permission.
