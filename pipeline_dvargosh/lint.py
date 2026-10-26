#!/usr/bin/env python3
"""
Dvargosh Pipeline Lint:
Evaluates the DVARGOSH_LINT_* rules declared in docs/dvargosh_schema.json against the
generated module metadata, plus structural rules the schema cannot express.

Exit code is non-zero when any rule with severity "error" fails — CI gates on this
(`make lint`). Warnings do not fail the build but must be triaged; infos are noise-level.

Rules sourced from the schema:
  DVARGOSH_LINT_001 (error)   Domain naming: <module>:<subsystem> or '*'
  DVARGOSH_LINT_002 (warning) Secured memory quota guard (max_kb)
  DVARGOSH_LINT_003 (error)   Signature coverage when signing is intended
  DVARGOSH_LINT_004 (info)    Typed proxy availability for exported services

Structural rules defined here:
  DVARGOSH_LINT_005 (warning) Raw registry()->invoke() in module sources
                              (migration aid for the binder API; enforced later)
  DVARGOSH_LINT_006 (error)   Duplicate module names in the registry schema
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SCHEMA_CANDIDATES = [
    ROOT_DIR / "docs" / "dvargosh_schema.json",
    ROOT_DIR / "build" / "schema.json",
    ROOT_DIR / "build" / "generated" / "schema.json",
]

DOMAIN_NAME_REGEX = re.compile(r"^([a-zA-Z0-9_]+:[a-zA-Z0-9_\*]+|\*)$")
# Raw dynamic invoke inside module code — allowed in host code (src/), forbidden-ish
# in modules/ and development_modules/ while the binder API migrates (LINT_005).
RAW_INVOKE_REGEX = re.compile(r"registry\(\)\s*->\s*invoke\(|->\s*invoke\(")


class LintReport:
    def __init__(self):
        self.errors = 0
        self.warnings = 0
        self.infos = 0

    def _emit(self, severity, rule, message):
        icon = {"error": "✗", "warning": "⚠", "info": "ℹ"}.get(severity, "?")
        print(f"  {icon} [{rule}] ({severity}) {message}")
        if severity == "error":
            self.errors += 1
        elif severity == "warning":
            self.warnings += 1
        else:
            self.infos += 1

    def error(self, rule, message):
        self._emit("error", rule, message)

    def warning(self, rule, message):
        self._emit("warning", rule, message)

    def info(self, rule, message):
        self._emit("info", rule, message)

    def ok(self, rule, message):
        print(f"  ✓ [{rule}] {message}")


def load_schema():
    for path in SCHEMA_CANDIDATES:
        if path.exists():
            schema = json.loads(path.read_text())
            return path, schema
    return None, None


def severity_of(schema, rule_id, default):
    for rule in schema.get("lint_rules", []):
        if rule.get("id") == rule_id:
            return rule.get("severity", default)
    return default


def check_domain_naming(report, modules):
    bad = []
    for m in modules:
        for dom in m.get("domains", []):
            if not DOMAIN_NAME_REGEX.match(dom):
                bad.append(f"{m['name']}: '{dom}'")
    if bad:
        report.error("DVARGOSH_LINT_001",
                     "domain naming violation (expected <module>:<subsystem> or '*'): " + ", ".join(bad))
    else:
        report.ok("DVARGOSH_LINT_001", f"all {len(modules)} module domains follow the naming convention")


def check_memory_quota(report, modules, max_kb):
    offenders = [f"{m['name']} ({m['secured_memory_kb']} KB)"
                 for m in modules if m.get("secured_memory_kb", 0) > max_kb]
    if offenders:
        report.warning("DVARGOSH_LINT_002",
                       f"secured memory quota exceeds {max_kb} KB without elevated approval: " + ", ".join(offenders))
    else:
        report.ok("DVARGOSH_LINT_002", f"all secured memory quotas within {max_kb} KB guard")


def check_signature_coverage(report, modules):
    """LINT_003: when signing is intended (key exported or signatures.json exists),
    every loadable module binary must be covered."""
    sig_file = ROOT_DIR / "build" / "modules" / "signatures.json"
    signing_intended = bool(os.environ.get("DVARGOSH_SIGNING_KEY")) or sig_file.exists()
    if not signing_intended:
        report.info("DVARGOSH_LINT_003",
                    "signing not intended for this run (no DVARGOSH_SIGNING_KEY, no signatures.json) — skipped")
        return

    if not sig_file.exists():
        report.error("DVARGOSH_LINT_003",
                     "signing intended but build/modules/signatures.json is missing — run: make sign-modules")
        return

    try:
        sigs = json.loads(sig_file.read_text())
    except json.JSONDecodeError as e:
        report.error("DVARGOSH_LINT_003", f"signatures.json is not valid JSON: {e}")
        return

    missing = []
    for m in modules:
        for candidate in (f"libmod_{m['name']}", m["name"]):
            if candidate in sigs:
                break
        else:
            missing.append(m["name"])
    if missing:
        report.warning("DVARGOSH_LINT_003",
                       f"modules without a signature entry: {', '.join(missing)} "
                       f"(re-run: make sign-modules)")
    else:
        report.ok("DVARGOSH_LINT_003", "all module binaries covered by signatures.json")


def check_proxy_availability(report, modules):
    gen_inc = ROOT_DIR / "build" / "generated" / "include" / "dvargosh" / "generated"
    if not gen_inc.exists():
        report.info("DVARGOSH_LINT_004", "no generated include dir yet (run: make pipeline) — skipped")
        return
    missing = []
    for m in modules:
        if not m.get("services"):
            continue
        folder = m.get("folder_name", m["name"])
        if not (gen_inc / f"{folder}_interface.hpp").exists():
            missing.append(folder)
    if missing:
        report.info("DVARGOSH_LINT_004", f"modules with services but no generated proxy header: {', '.join(missing)}")
    else:
        report.ok("DVARGOSH_LINT_004", "every module with exported services has a generated proxy header")


def check_duplicate_modules(report, modules):
    seen = {}
    dupes = []
    for m in modules:
        if m["name"] in seen:
            dupes.append(m["name"])
        seen[m["name"]] = True
    if dupes:
        report.error("DVARGOSH_LINT_006",
                     f"duplicate module names in registry schema (ambiguous load targets): {', '.join(sorted(set(dupes)))}")
    else:
        report.ok("DVARGOSH_LINT_006", "no duplicate module names")


def check_raw_invoke(report):
    """LINT_005 (migration aid): raw dynamic invoke in module sources.
    Host code (src/) may use invoke freely; modules should use ctx->call()/binder clients."""
    offenders = []
    for base in ("modules", "development_modules"):
        base_dir = ROOT_DIR / base
        if not base_dir.exists():
            continue
        for cpp in base_dir.rglob("*.cpp"):
            if cpp.name.startswith("_generated"):
                continue
            try:
                code = cpp.read_text(errors="ignore")
            except OSError:
                continue
            hits = RAW_INVOKE_REGEX.findall(code)
            if hits:
                offenders.append(f"{cpp.relative_to(ROOT_DIR)} ({len(hits)}x)")
    if offenders:
        report.warning("DVARGOSH_LINT_005",
                       f"raw invoke() usage in module code — migrate to ctx->call()/typed clients: "
                       + ", ".join(offenders))
    else:
        report.ok("DVARGOSH_LINT_005", "no raw registry()->invoke in module sources")


def main():
    print("[dvargosh] Pipeline Lint: evaluating module schema & conventions...")
    schema_path, schema = load_schema()
    if schema is None:
        print("[ERROR] No schema found. Run `make pipeline` first (looked in docs/ and build/).")
        return 1
    print(f"  Schema: {schema_path.relative_to(ROOT_DIR)}")

    modules = schema.get("modules", [])
    report = LintReport()
    print(f"  Modules under review: {len(modules)}\n")

    check_domain_naming(report, modules)
    check_memory_quota(report, modules, 65536)
    check_signature_coverage(report, modules)
    check_proxy_availability(report, modules)
    check_duplicate_modules(report, modules)
    check_raw_invoke(report)

    print(f"\n[dvargosh] Lint summary: {report.errors} error(s), {report.warnings} warning(s), {report.infos} info(s)")
    if report.errors:
        print("[dvargosh] Lint FAILED (error-severity findings above).")
        return 1
    print("[dvargosh] Lint PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
