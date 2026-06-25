#!/usr/bin/env python3
"""
maclpe — macOS privileged-helper LPE analyzer (Phase 1)
Detects the privileged-helper client-authorization-bypass class:
  C1 unauthenticated | C2 world-writable socket | C3 PID-racy | C4 team-req + injectable client | C5 cmd-inj | SECURE

The Phase-1 win over the old triage.sh: it classifies the *runtime* requirement (identifier-pinned vs
team-only) and checks *client injectability*, which is what made Waves Central a false-"SECURE".

Usage:
  maclpe.py --app "/Volumes/Waves Central 16.7.2/Waves Central.app"
  maclpe.py --helper /path/to/helperbinary [--bundle /path/to/App.app]
"""
import argparse, glob, json, os, plistlib, re, subprocess, sys, tempfile

R2 = "/opt/homebrew/bin/radare2" if os.path.exists("/opt/homebrew/bin/radare2") else "radare2"

AUDIT  = ["xpc_connection_get_audit_token", "kSecGuestAttributeAudit",
          "SecCodeCreateWithXPCMessage", "codeWithAuditToken", "forAuditToken"]
PIDM   = ["kSecGuestAttributePid", "xpc_connection_get_pid"]
AUTHZ  = ["AuthorizationCopyRights", "AuthorizationCreateFromExternalForm"]
REQCHK = ["SecRequirementCreateWithString", "SecCodeCheckValidity",
          "setCodeSigningRequirement", "codeSigningMatches"]
XPC    = ["shouldAcceptNewConnection", "NSXPCListener", "xpc_main"]
DANGER = re.compile(r"execute|exec|runScript|install|writeFile|overwrite|copyItem|chown|"
                    r"setOwner|chmod|setPermissions|symlink|setPreferences|installPkg|deleteFile", re.I)
INJ_ENTS = ["disable-library-validation", "allow-unsigned-executable-memory",
            "allow-dyld-environment-variables", "get-task-allow"]


def sh(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr
    except Exception:
        return ""


def archs(b):
    out = sh(["lipo", "-archs", b]).split()
    return out or ["native"]


def thin(b, a):
    if a == "native":
        return b, False
    fd, t = tempfile.mkstemp(suffix=".bin"); os.close(fd)
    r = subprocess.run(["lipo", "-thin", a, b, "-output", t], capture_output=True)
    return (t, True) if r.returncode == 0 else (b, False)


def blob_of(b):
    """union nm symbols + strings across all arch slices."""
    out = ""
    for a in archs(b):
        t, tmp = thin(b, a)
        out += sh(["nm", "-u", t]) + "\n" + sh(["nm", t]) + "\n" + sh(["strings", "-a", "-n", "5", t]) + "\n"
        if tmp:
            try: os.unlink(t)
            except OSError: pass
    return out


def codesign_info(b):
    out = sh(["codesign", "-dvvv", b])
    ident = re.search(r"Identifier=(\S+)", out)
    team = re.search(r"TeamIdentifier=(\S+)", out)
    flags = re.search(r"flags=0x[0-9a-f]+\(([^)]*)\)", out)
    return {
        "identifier": ident.group(1) if ident else None,
        "team": team.group(1) if team else None,
        "hardened_runtime": "runtime" in (flags.group(1) if flags else ""),
        "apple_signed": "Authority=Software Signing" in out or "Authority=Apple Code Signing" in out,
    }


def entitlements(b):
    out = sh(["codesign", "-d", "--entitlements", ":-", b])
    return {k for k in INJ_ENTS if k in out}


def injectability(b):
    info = codesign_info(b)
    ents = entitlements(b)
    if not info["hardened_runtime"]:
        return "HIGH", ents, "no hardened runtime"
    if "get-task-allow" in ents:
        return "HIGH", ents, "get-task-allow"
    if "allow-dyld-environment-variables" in ents and "disable-library-validation" in ents:
        return "HIGH", ents, "allow-dyld-env + disable-library-validation"
    if "allow-dyld-environment-variables" in ents:
        return "COND", ents, "allow-dyld-env only (same-team dylib needed)"
    return "NO", ents, "hardened runtime + library validation"


def code_xrefs_to_string(b, s):
    """count code xrefs to a string literal via radare2 — distinguishes runtime-used vs Info.plist-only."""
    out = sh([R2, "-q", "-e", "scr.color=0", "-c", "aa 2>/dev/null; axt @ str.%s" % s, b])
    return len([ln for ln in out.splitlines() if "0x" in ln and ("CALL" in ln or "DATA" in ln or "CODE" in ln or "ldr" in ln or "adr" in ln)])


def classify_requirement(b):
    """returns (class, pinned_identifier, evidence). The Waves-fix: identifier in Info.plist alone != pinned;
    it must be referenced from code at runtime."""
    s = sh(["strings", "-a", b])
    ids = sorted(set(re.findall(r'identifier &quot;([\w.\-]+)&quot;', s) +
                     re.findall(r'identifier "([\w.\-]+)"', s)))
    team_clause = bool(re.search(r"subject\.OU", s))
    anchor = bool(re.search(r"anchor apple", s))
    for cid in ids:
        if code_xrefs_to_string(b, cid) > 0:
            return "IDENTIFIER-PINNED", cid, "identifier '%s' referenced from runtime code" % cid
    if ids and team_clause:
        return "TEAM-ONLY", None, "identifier present only in Info.plist (no runtime code xref); runtime check is team/OU"
    if team_clause:
        return "TEAM-ONLY", None, "subject.OU clause, no identifier"
    if anchor:
        return "ANCHOR-ONLY", None, "anchor apple only"
    return "NONE", None, "no requirement string found"


def find_helpers(app, fast=False):
    helpers = set()
    for pat in ("**/Library/LaunchServices/*", "**/*PrivilegedHelper*", "**/Library/LaunchDaemons/*"):
        for p in glob.glob(os.path.join(app, pat), recursive=True):
            if os.path.isfile(p) and os.access(p, os.X_OK):
                helpers.add(p)
    if not fast:
        # expensive: any Mach-O with shouldAcceptNewConnection
        for p in glob.glob(os.path.join(app, "**"), recursive=True):
            if os.path.isfile(p) and os.access(p, os.X_OK) and "Mach-O" in sh(["file", p]):
                if "shouldAcceptNewConnection" in sh(["strings", "-a", p]):
                    helpers.add(p)
    return sorted(helpers)


SEVRANK = {"C1": 0, "C2": 1, "C4": 2, "C5": 3, "C3": 4, "UNKNOWN": 5, "SECURE": 6, "SKIP": 7}


def scan_dir(roots):
    apps = []
    for root in roots.split(","):
        apps += glob.glob(os.path.join(root, "*.app"))
        apps += glob.glob(os.path.join(root, "*", "*.app"))      # corpus ex/ layout
        apps += glob.glob(os.path.join(root, "*", "ex", "*.app"))
    rows = []
    for app in sorted(set(apps)):
        try:
            helpers = find_helpers(app, fast=True)
        except Exception:
            continue
        for h in helpers:
            try:
                rows.append((app, analyze(h, app)))
            except Exception:
                continue
    rows.sort(key=lambda r: (SEVRANK.get(r[1]["subclass"], 9), r[0]))
    print("%-7s %-9s %-30s %-34s %s" % ("CLASS", "SEV", "APP", "HELPER", "REQ-CLASS"))
    print("-" * 110)
    for app, f in rows:
        print("%-7s %-9s %-30s %-34s %s" % (
            f["subclass"], f["severity"], os.path.basename(app)[:30],
            os.path.basename(f["helper"])[:34], f["requirement_class"]))
    print("\n%d helpers across %d app(s). Re-run with --app on any C1/C4 for full detail."
          % (len(rows), len({r[0] for r in rows})))


def client_binary_for_id(bundle, cid):
    for ip in glob.glob(os.path.join(bundle, "**", "Info.plist"), recursive=True):
        try:
            with open(ip, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        if pl.get("CFBundleIdentifier") == cid:
            exe = pl.get("CFBundleExecutable")
            cand = os.path.join(os.path.dirname(ip), "MacOS", exe) if exe else None
            if cand and os.path.exists(cand):
                return cand
    return None


def same_team_injectable_apps(bundle, team):
    out = []
    for ip in glob.glob(os.path.join(bundle, "**", "Info.plist"), recursive=True):
        try:
            with open(ip, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        exe = pl.get("CFBundleExecutable")
        cand = os.path.join(os.path.dirname(ip), "MacOS", exe) if exe else None
        if not cand or not os.path.exists(cand):
            continue
        info = codesign_info(cand)
        if info["team"] != team:
            continue
        lvl, ents, why = injectability(cand)
        if lvl == "HIGH":
            out.append({"id": pl.get("CFBundleIdentifier"), "path": cand, "injectable": lvl,
                        "entitlements": sorted(ents), "why": why})
    return out


def analyze(helper, bundle):
    info = codesign_info(helper)
    b = blob_of(helper)
    has = lambda lst: any(m in b for m in lst)
    methods = sorted(set(m for m in re.findall(r"[A-Za-z][A-Za-z0-9_:]{4,}", b) if DANGER.search(m)))[:12]
    req_class, pinned, req_ev = classify_requirement(helper)

    clients = []
    if pinned:
        cb = client_binary_for_id(bundle, pinned) if bundle else None
        if cb:
            lvl, ents, why = injectability(cb)
            clients.append({"id": pinned, "path": cb, "injectable": lvl,
                            "entitlements": sorted(ents), "why": why, "role": "pinned"})
    elif req_class in ("TEAM-ONLY", "ANCHOR-ONLY") and bundle:
        clients = [{**c, "role": "same-team"} for c in same_team_injectable_apps(bundle, info["team"])]

    f = {
        "helper": helper, "identifier": info["identifier"], "team": info["team"],
        "apple_signed": info["apple_signed"], "hardened_runtime": info["hardened_runtime"],
        "xpc_listener": has(XPC),
        "auth": {"audit_token": has(AUDIT), "pid_only": has(PIDM) and not has(AUDIT),
                 "authorization_api": has(AUTHZ), "req_check": has(REQCHK)},
        "requirement_class": req_class, "pinned_identifier": pinned, "requirement_evidence": req_ev,
        "dangerous_methods": methods, "clients": clients,
    }
    f["subclass"], f["severity"], f["verdict"] = score(f)
    return f


def score(f):
    if f["apple_signed"]:
        return "SKIP", "none", "Apple/system-signed — out of scope"
    a = f["auth"]
    has_danger = bool(f["dangerous_methods"])
    inj_high = [c for c in f["clients"] if c["injectable"] == "HIGH"]

    if not a["audit_token"] and not a["authorization_api"] and f["requirement_class"] == "NONE" and f["xpc_listener"]:
        return "C1", "critical", "UNAUTHENTICATED: no client validation on a privileged IPC listener"
    if f["requirement_class"] in ("TEAM-ONLY", "ANCHOR-ONLY") and inj_high and has_danger:
        return "C4", "high", ("INJECTABLE-CLIENT: requirement is %s and an authorized client is injectable "
                              "(%s) — exploitable even with audit-token present"
                              % (f["requirement_class"], inj_high[0]["id"]))
    if a["pid_only"]:
        return "C3", "low", "PID-based validation (racy/TOCTOU) — verify practical winnability, deprioritize"
    if f["requirement_class"] == "IDENTIFIER-PINNED" and a["audit_token"] and not inj_high:
        return "SECURE", "none", ("identifier-pinned to '%s' (non-injectable) + audit-token"
                                  % f["pinned_identifier"])
    return "UNKNOWN", "review", "could not establish full chain — DEEP RE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", help="path to an .app bundle (finds helpers + clients automatically)")
    ap.add_argument("--helper", help="path to a single helper binary")
    ap.add_argument("--bundle", help="bundle root for client lookup when using --helper")
    ap.add_argument("--scan-dir", help="comma-separated dirs of .app bundles; prints app->verdict table")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    if args.scan_dir:
        scan_dir(args.scan_dir); return

    findings = []
    if args.app:
        helpers = find_helpers(args.app)
        if not helpers:
            print("[!] no privileged helper / XPC listener found in", args.app); return
        for h in helpers:
            findings.append(analyze(h, args.app))
    elif args.helper:
        findings.append(analyze(args.helper, args.bundle))
    else:
        ap.error("need --app or --helper")

    if args.json:
        print(json.dumps(findings, indent=2)); return
    for f in findings:
        print("=" * 78)
        print("HELPER   :", f["helper"])
        print("identity :", f["identifier"], "| team", f["team"], "| hardened_runtime", f["hardened_runtime"])
        print("auth     :", {k: v for k, v in f["auth"].items()})
        print("req-class: %-17s  (%s)" % (f["requirement_class"], f["requirement_evidence"]))
        if f["dangerous_methods"]:
            print("methods  :", ", ".join(f["dangerous_methods"][:6]))
        for c in f["clients"]:
            print("client   : %-40s injectable=%s (%s)" % (c["id"], c["injectable"], c["why"]))
        print(">>> %-7s [%s]  %s" % (f["subclass"], f["severity"].upper(), f["verdict"]))


if __name__ == "__main__":
    main()
