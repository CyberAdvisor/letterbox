#!/usr/bin/env python3
"""
Letterbox — Doc-vs-Code Audit
==============================
Verifies that all documentation matches the current state of the code.
Exits 0 if clean, 1 if any check fails.

Run from inside letterbox_code/:
    python3 audit_docs.py
"""
import sys, re, ast
sys.path.insert(0, '.')

results = []
def ok(check, detail=""):   results.append(("OK",   check, detail))
def fail(check, detail=""): results.append(("FAIL", check, detail))
def warn(check, detail=""): results.append(("WARN", check, detail))

code = {f: open(f).read() for f in [
    "core/constants.py","store/vault.py","main.py","store/config.py",
    "store/history.py","store/credentials.py","core/pad.py",
    "core/message.py","util/random.py","transport/posteo.py",
]}
docs = {f: open(f).read() for f in [
    "CHANGELOG.md","HANDOFF.md","DESIGN.md","TECHNICAL_OVERVIEW.md",
    "INSTALL.md","THREAT_MODEL.md","README.md",
]}

from core.constants import (
    PAD_SIZE, PAD_COUNT, PAD_ASSIGN_SIZE, TRANSMISSION_SIZE,
    MAX_CONTENT_BYTES, VAULT_VERSION, VAULT_MAGIC, TRANSFER_MAGIC,
    VAULT_FLAGS_SIZE, VAULT_FLAG_EPHEMERAL,
    KDF_ITERATIONS, KDF_TRANSFER_ITERATIONS, HISTORY_PAGE_SIZE,
    MAX_PASSPHRASE_ATTEMPTS,
)
from store.config import CONFIG_FILE_SIZE
from util.random import generate_transfer_passphrase

# ── 1. Magic bytes ──────────────────────────────────────────────────────────
for val, name in [(VAULT_MAGIC, "VAULT_MAGIC"), (TRANSFER_MAGIC, "TRANSFER_MAGIC")]:
    expected = b'LBVAULT2' if "VAULT" in name else b'LBTRANS2'
    (ok if val == expected else fail)(f"{name} = {expected}", f"got {val}")

non_changelog = {k:v for k,v in docs.items() if k != "CHANGELOG.md"}
for doc, src in non_changelog.items():
    for old in ["LBVAULT1", "LBTRANS1"]:
        if old in src:
            fail(f"Stale magic {old} in {doc}")

changelog = docs["CHANGELOG.md"]
for old in ["LBVAULT1", "LBTRANS1"]:
    if old in changelog:
        if re.search(rf'from\s+{old}|{re.escape(old)}\s*/|/\s*{re.escape(old)}', changelog):
            ok(f"CHANGELOG references {old} only in historical transition context")
        else:
            fail(f"CHANGELOG uses {old} outside historical context")

if "LBVAULT2" in docs["TECHNICAL_OVERVIEW.md"] and "LBTRANS2" in docs["TECHNICAL_OVERVIEW.md"]:
    ok("TECHNICAL_OVERVIEW references current LBVAULT2/LBTRANS2")
else:
    fail("TECHNICAL_OVERVIEW missing LBVAULT2/LBTRANS2")

# ── 2. Vault format constants ───────────────────────────────────────────────
(ok if VAULT_VERSION == 2 else fail)("VAULT_VERSION = 2", f"got {VAULT_VERSION}")
(ok if VAULT_FLAGS_SIZE == 2 else fail)("VAULT_FLAGS_SIZE = 2", f"got {VAULT_FLAGS_SIZE}")
(ok if VAULT_FLAG_EPHEMERAL == 0x0001 else fail)("VAULT_FLAG_EPHEMERAL = 0x0001")

# ── 3. VaultData attributes ─────────────────────────────────────────────────
vault_src = code["store/vault.py"]
for attr in ["ephemeral", "erase_pad", "bytearray"]:
    (ok if attr in vault_src else fail)(f"vault.py contains '{attr}'")

# ── 4. main.py ephemeral handling ───────────────────────────────────────────
main_src = code["main.py"]
for phrase in ["vault.ephemeral", "erase_pad",
               "save_sent", "ephemeral=ephemeral"]:
    (ok if phrase in main_src else fail)(f"main.py contains '{phrase}'")

# ── 5. generate_vault signature ─────────────────────────────────────────────
for node in ast.walk(ast.parse(vault_src)):
    if isinstance(node, ast.FunctionDef) and node.name == "generate_vault":
        (ok if "ephemeral" in [a.arg for a in node.args.args] else
         fail)("generate_vault has ephemeral parameter")
        break

# ── 6. Config file size ─────────────────────────────────────────────────────
(ok if CONFIG_FILE_SIZE == 61 else fail)("CONFIG_FILE_SIZE = 61", f"got {CONFIG_FILE_SIZE}")

# ── 7. Key numbers in TECHNICAL_OVERVIEW ───────────────────────────────────
for value, label in [
    ("1024",     "PAD_SIZE"),
    ("1032",     "TRANSMISSION_SIZE"),
    ("200,000",  "KDF_ITERATIONS"),
    ("2,000,000","KDF_TRANSFER_ITERATIONS"),
    ("61",       "CONFIG_FILE_SIZE"),
]:
    (ok if value in docs["TECHNICAL_OVERVIEW.md"] else warn)(
        f"TECHNICAL_OVERVIEW contains {label} ({value})")

# ── 8. Transfer passphrase ──────────────────────────────────────────────────
phrase = generate_transfer_passphrase()
(ok if len(phrase.split()) == 6 else fail)("generate_transfer_passphrase produces 6 words")
(ok if "six" in docs["INSTALL.md"].lower() else warn)("INSTALL.md mentions six-word passphrase")

# ── 9. Ephemeral coverage in all required docs ──────────────────────────────
for doc in ["CHANGELOG.md","HANDOFF.md","DESIGN.md","TECHNICAL_OVERVIEW.md",
            "INSTALL.md","THREAT_MODEL.md"]:
    (ok if "ephemeral" in docs[doc].lower() else fail)(f"{doc} mentions ephemeral mode")

# ── 10. INSTALL transport correctness ──────────────────────────────────────
(ok if "Posteo" in docs["INSTALL.md"] else fail)("INSTALL.md describes Posteo vault exchange")
if re.search(r'icloud.{0,40}(share|folder).{0,60}vault', docs["INSTALL.md"], re.I):
    fail("INSTALL.md still describes iCloud folder sharing for vault")
else:
    ok("INSTALL.md does not describe iCloud folder sharing for vault")

# ── 11. TECHNICAL_OVERVIEW data flow completeness ──────────────────────────
to = docs["TECHNICAL_OVERVIEW.md"]
for phrase in ["erase_pad", "ephemeral mode", "standard mode"]:
    (ok if phrase.lower() in to.lower() else fail)(f"TECHNICAL_OVERVIEW contains '{phrase}'")

# main.py ephemeral prompt is now a single Press Enter
(ok if "Press Enter to delete" in code["main.py"] else fail)(
    "main.py contains ephemeral delete prompt")

# ── 12. Version numbers ─────────────────────────────────────────────────────
(ok if "v1.1.0" in docs["HANDOFF.md"] else fail)("HANDOFF.md shows v1.1.0")
(ok if "2.0" in docs["README.md"] else fail)("README.md shows version 2.0")
(ok if "1.1.0" in docs["CHANGELOG.md"] else fail)("CHANGELOG.md has 1.1.0 entry")

# ── 13. No stale current-version claims ────────────────────────────────────
for doc, src in docs.items():
    if doc == "CHANGELOG.md": continue
    if re.search(r'[Cc]urrent[^\n]{0,20}v?1\.0\.2|v?1\.0\.2[^\n]{0,20}[Cc]urrent', src):
        fail(f"{doc} still labels v1.0.2 as current")

# ── 14. THREAT_MODEL post-session coverage ─────────────────────────────────
(ok if "ephemeral" in docs["THREAT_MODEL.md"].lower() else fail)(
    "THREAT_MODEL.md covers ephemeral mode")
(ok if "after a session" in docs["THREAT_MODEL.md"].lower() else fail)(
    "THREAT_MODEL.md covers post-session device forensics")

# ── 15. DESIGN.md ephemeral rationale ──────────────────────────────────────
(ok if "erase" in docs["DESIGN.md"].lower() and "ephemeral" in docs["DESIGN.md"].lower() else fail)(
    "DESIGN.md documents ephemeral design decisions")

# ── 15b. APP_VERSION constant used in menu (not hardcoded) ────────────────
main_src = code["main.py"]
if 'APP_VERSION' in main_src and '"Letterbox v1.' not in main_src:
    ok("main.py uses APP_VERSION constant for menu title (not hardcoded)")
else:
    fail("main.py has hardcoded version string in menu title")

# ── 16. No stale magic in source files ─────────────────────────────────────
stale = [f for f, s in code.items() if "LBVAULT1" in s or "LBTRANS1" in s]
(ok if not stale else fail)("No stale v1 magic bytes in source files", str(stale) if stale else "")

# ── Summary ─────────────────────────────────────────────────────────────────
print()
print("=" * 60)
print("DOC-VS-CODE AUDIT")
print("=" * 60)
fails = [r for r in results if r[0] == "FAIL"]
warns = [r for r in results if r[0] == "WARN"]
oks   = [r for r in results if r[0] == "OK"]
for status, check, detail in results:
    colour = "\033[32m" if status=="OK" else "\033[33m" if status=="WARN" else "\033[31m"
    suffix = f" ({detail})" if detail else ""
    print(f"  {colour}{status}\033[0m  {check}{suffix}")
print()
print(f"  {len(oks)} OK   {len(warns)} WARN   {len(fails)} FAIL")
if fails:
    print("\n  FAILURES — documentation does not match code")
    sys.exit(1)
else:
    print("\n  Documentation matches code.")
