# maclpe — macOS Privileged-Helper LPE Auditor

A static auditor that finds the **insecure-XPC / incorrect-authorization** class of local
privilege-escalation (LPE) bug in macOS privileged helper tools (`SMJobBless` root helpers).

It answers one question that simple symbol-grep triage gets wrong: **does this root helper actually
verify *who* is allowed to talk to it — and is that "trusted" client even safe to trust?**

---

## The bug class

A privileged helper installed via `SMJobBless` runs as **root** and exposes IPC (an `NSXPCConnection`
Mach service and/or a unix-domain socket). It performs privileged actions — file writes, installs,
`chown`/`chmod`, command execution — on behalf of a client. The LPE exists when a non-root local
process can reach those actions because the helper's **client authorization is missing, weak, or
bypassable** (CWE-306 / CWE-862 / CWE-863 / CWE-269).

The subtle, high-impact variant: the helper *does* check the caller's code signature, but only against
the developer's **Team Identifier** (a "same-developer" requirement) instead of a specific bundle
**identifier** — and the developer ships an app that is **injectable** (e.g. the
`com.apple.security.cs.disable-library-validation` entitlement). An attacker injects a library into
that legitimately-signed-but-injectable process and, from inside it, passes the Team-ID check and
drives the root helper. Pinning the client *identifier* is the fix.

## Why this auditor is different

Marker-only triage flags a helper **secure** the moment it sees an `audit_token` /
`SecRequirement` check. That produces **false negatives** — a present check is not a *sufficient*
check. `maclpe` evaluates **both axes** of the authorization:

1. **What the requirement binds** — it classifies the *runtime* code-signing requirement as
   `IDENTIFIER-PINNED` (strong) vs `TEAM-ONLY` / `ANCHOR-ONLY` (weak) vs `NONE`. It distinguishes an
   identifier that is merely present in `Info.plist`/`SMAuthorizedClients` from one that is actually
   *referenced by runtime code* (via cross-reference analysis).
2. **Whether the authorized client is injectable** — it locates the client binary and scores
   injectability from its entitlements and Hardened-Runtime state (Library Validation,
   `disable-library-validation`, `allow-dyld-environment-variables`, `get-task-allow`).

Only `identifier-pinned requirement` **and** `non-injectable client` **and** `audit-token` is reported
as **SECURE**.

## Sub-class taxonomy

| Class | Meaning | CWE |
|---|---|---|
| **C1** | No client validation on a privileged IPC listener (unauthenticated root) | 306 / 862 |
| **C2** | World-writable (`0666`) unix socket to a root daemon | 732 |
| **C3** | PID-based validation (racy / TOCTOU — usually not practically winnable) | 367 |
| **C4** | Team-only requirement **+** an injectable authorized client | 863 / 269 |
| **C5** | Command injection in the helper (`popen`/`system`/`NSTask`) | 78 |
| **SECURE** | Identifier-pinned requirement + non-injectable client + audit-token | — |

## Requirements

macOS, with the standard toolchain: `codesign`, `otool`, `nm`, `lipo`, `strings` (Xcode CLT) and
[`radare2`](https://github.com/radareorg/radare2) (for the requirement cross-reference check).
Python 3.8+. No third-party Python packages.

## Usage

```bash
# audit a single application bundle (finds helpers + their clients automatically)
python3 maclpe.py --app "/Applications/Some App.app"

# audit one helper binary, with its bundle for client lookup
python3 maclpe.py --helper /path/to/helper --bundle "/Applications/Some App.app"

# sweep a directory of .app bundles -> app -> verdict table
python3 maclpe.py --scan-dir /Applications

# machine-readable
python3 maclpe.py --app "/Applications/Some App.app" --json
```

### Example output

```
HELPER   : .../Library/LaunchServices/com.vendor.app.InstlHelper
identity : com.vendor.app.InstlHelper | team XXXXXXXXXX | hardened_runtime True
auth     : {'audit_token': True, 'authorization_api': True, 'pid_only': False, 'req_check': True}
req-class: TEAM-ONLY   (identifier present only in Info.plist; runtime check is team/OU)
client   : com.vendor.app  injectable=HIGH (allow-dyld-env + disable-library-validation)
>>> C4  [HIGH]  INJECTABLE-CLIENT: requirement is TEAM-ONLY and an authorized client is injectable
               — exploitable even with audit-token present
```

## How it works

```
acquire/locate helper  ->  analyze helper (identity, IPC, auth markers, dangerous methods)
                       ->  classify runtime code-signing requirement
                       ->  analyze authorized-client injectability
                       ->  score sub-class (C1..C5 / SECURE)
```

Symbols and strings are unioned across all architecture slices; the requirement classifier uses
binary cross-reference analysis to tell an enforced runtime identifier from one that only appears in
the bundle's `Info.plist`.

## Responsible use & disclosure

This is a **defensive auditing / research** tool. Run it only against software you are authorized to
test (your own machine, your own products, or research under a coordinated-disclosure process). It
reports **candidates**, not confirmed exploits — every flagged helper needs manual confirmation that
a dangerous method is actually reachable. Findings against third-party software must go through
**coordinated disclosure**: report privately to the vendor, do not publish proof-of-concept code, and
allow time for a fix. Do not use this tool to attack systems you do not own or have permission to test.

## Status / roadmap

- ✅ **P1** — helper analysis, runtime requirement classification, client-injectability scoring,
  sub-class verdict, directory sweep. (Regression-validated against known vulnerable **and** patched
  builds of a commercial installer helper.)
- ⏳ **P2** — JSON/SQLite finding store, corpus diffing, dedup-against-known-CVEs gate.
- ⏳ **P3** — Objective-C method/type-encoding recovery for precise method targeting.
- ⏳ **P4** — *defensive* PoC scaffolding (benign root-proof only, generation-gated, never weaponized).

## License

MIT — see `LICENSE`.
