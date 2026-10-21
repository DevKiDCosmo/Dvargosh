#!/usr/bin/env python3
"""
Dvargosh Meta Header Pipeline Tool:
- Extracts comprehensive metadata from module.def manifests and C++ service annotations.
- Generates static, non-allocating C/C++ metadata headers (_module_header.hpp and _module_header.cpp)
  embedding ModuleHeaderRaw directly into the dynamic module's .rodata.
- Writes companion JSON metadata manifests (<name>.meta.json) for zero-execution discovery.
- Provides a secure inspection mechanism allowing the runtime to validate ABI, versions,
  build hashes, domains, quotas, and permissions BEFORE initializing or calling module factory code.
"""

import os
import sys
import re
import argparse
import configparser
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT_DIR / "modules"
DEV_MODULES_DIR = ROOT_DIR / "development_modules"
BUILD_MODULES_DIR = ROOT_DIR / "build" / "modules"

DVARGOSH_ABI_VERSION = "dvargosh-abi-v1"
DVARGOSH_HEADER_MAGIC = "0x48534F4752415644ULL"  # "DVARGOSH"

def cpp_escape(s: str) -> str:
    """Escapes string for safe embedding into C++ string literals."""
    return json.dumps(s)[1:-1]

PERMISSION_MASKS = {
    "None": 0,
    "MemoryExpand": 1 << 0,
    "FileIO": 1 << 1,
    "NetworkAccess": 1 << 2,
    "ServiceRegister": 1 << 3,
    "DynamicInvoke": 1 << 4,
    "EventPublish": 1 << 5,
    "EventSubscribe": 1 << 6,
    "SecuredMemory": 1 << 7,
    "SystemInfo": 1 << 8,
    "Admin": 0xFFFFFFFF
}

def parse_version(v_str: str):
    parts = v_str.strip().split(".")
    major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 1
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return major, minor, patch

def compute_module_build_id(folder: Path) -> str:
    hasher = hashlib.sha256()
    for f in sorted(folder.glob("*")):
        if f.is_file() and not f.name.startswith("_"):
            try:
                hasher.update(f.name.encode("utf-8"))
                hasher.update(f.read_bytes())
            except Exception:
                pass
    return "bld_" + hasher.hexdigest()[:16]

def scan_services(folder: Path):
    services = []
    attr_regex = re.compile(
        r'(?:DVARGOSH_SERVICE|DVARGOSH_FN)\s*\(\s*([a-zA-Z0-9_:\*]+)\s*\)|'
        r'\[\[\s*dvargosh::(?:service|fn)\s*\(\s*"([^"]+)"\s*\)\s*\]\]|'
        r'\[\[\s*([a-zA-Z0-9_]+:[a-zA-Z0-9_]+)\s*\]\]',
        re.MULTILINE
    )

    for cpp in sorted(folder.glob("*.cpp")):
        if cpp.name.startswith("_"):
            continue
        try:
            code = cpp.read_text(errors="ignore")
        except Exception:
            continue

        exp_matches = re.findall(
            r'DVARGOSH_EXPORT_FN\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)',
            code
        )
        for fn_name, domain, desc in exp_matches:
            services.append({"name": fn_name, "domain": domain, "desc": desc})

        for match in attr_regex.finditer(code):
            domain = match.group(1) or match.group(2) or match.group(3)
            after_pos = match.end()
            rest = code[after_pos:after_pos + 400]
            fn_match = re.search(r'^\s*([a-zA-Z0-9_:<>\s\*&]+?)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*\{', rest, re.MULTILINE)
            if fn_match:
                fn_name = fn_match.group(2).strip()
                services.append({"name": fn_name, "domain": domain, "desc": f"Attributed service '{fn_name}'"})

    return services

def read_module_info(folder: Path):
    name = folder.name
    def_file = folder / "module.def"
    version_str = "1.0.0"
    desc = f"Dvargosh plug-and-play module '{name}'"
    author = "Dvargosh Team"
    secured_kb = 2048
    domains = ["*"]
    raw_perms = ["ServiceRegister", "DynamicInvoke", "EventPublish", "EventSubscribe", "SecuredMemory"]

    if def_file.exists():
        cfg = configparser.ConfigParser()
        try:
            cfg.read(def_file)
            if "module" in cfg:
                sec = cfg["module"]
                name = sec.get("name", name).strip()
                version_str = sec.get("version", version_str).strip()
                desc = sec.get("description", desc).strip()
                author = sec.get("author", author).strip()
                secured_kb = sec.getint("secured_memory_kb", secured_kb)
                if "domains" in sec:
                    domains = [d.strip() for d in sec.get("domains").split(",") if d.strip()]
                if "permissions" in sec:
                    raw_perms = [p.strip() for p in sec.get("permissions").split(",") if p.strip()]
        except Exception as e:
            print(f"[ERROR] Failed parsing {def_file}: {e}", file=sys.stderr)
            sys.exit(1)

    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"[ERROR] Invalid module name '{name}' in {folder}: must match ^[a-zA-Z0-9_]+$", file=sys.stderr)
        sys.exit(1)

    services = scan_services(folder)
    for s in services:
        if s["domain"] not in domains and s["domain"] != "*":
            domains.append(s["domain"])

    if "*" not in domains:
        domains.append("*")

    perm_mask = 0
    for p in raw_perms:
        perm_mask |= PERMISSION_MASKS.get(p, 0)

    major, minor, patch = parse_version(version_str)
    build_id = compute_module_build_id(folder)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "folder": folder,
        "name": name,
        "version_str": version_str,
        "version_major": major,
        "version_minor": minor,
        "version_patch": patch,
        "abi_version": DVARGOSH_ABI_VERSION,
        "build_id": build_id,
        "build_timestamp": timestamp,
        "compiler_info": "Clang / GCC C++17 Compatible",
        "domain": domains[0] if domains else "default",
        "supported_domains": domains,
        "secured_memory_kb": secured_kb,
        "permissions_mask": perm_mask,
        "permissions_list": raw_perms,
        "description": desc,
        "author": author,
        "services": services
    }

def generate_header_files(info: dict, out_meta_dir: Path = None):
    folder = info["folder"]
    hpp_file = folder / "_module_header.hpp"
    cpp_file = folder / "_module_header.cpp"

    domains_csv = ", ".join(info["supported_domains"])
    svc_names = [f"{info['name']}.{s['name']}" for s in info["services"]]
    services_csv = ", ".join(svc_names)
    svc_count = len(svc_names)

    esc_name = cpp_escape(info["name"])
    esc_version_str = cpp_escape(info["version_str"])
    esc_abi = cpp_escape(info["abi_version"])
    esc_build_id = cpp_escape(info["build_id"])
    esc_timestamp = cpp_escape(info["build_timestamp"])
    esc_compiler = cpp_escape(info["compiler_info"])
    esc_domain = cpp_escape(info["domain"])
    esc_domains = cpp_escape(domains_csv)
    esc_desc = cpp_escape(info["description"])
    esc_author = cpp_escape(info["author"])
    esc_services = cpp_escape(services_csv)

    # 1. Generate _module_header.hpp
    hpp_lines = [
        "// Auto-generated by Dvargosh Meta Header Tool. DO NOT EDIT.",
        "#pragma once",
        "",
        "#include \"dvargosh/module_header.hpp\"",
        "",
        f"#define DVARGOSH_MOD_NAME \"{esc_name}\"",
        f"#define DVARGOSH_MOD_VERSION_STR \"{esc_version_str}\"",
        f"#define DVARGOSH_MOD_VERSION_MAJOR {info['version_major']}",
        f"#define DVARGOSH_MOD_VERSION_MINOR {info['version_minor']}",
        f"#define DVARGOSH_MOD_VERSION_PATCH {info['version_patch']}",
        f"#define DVARGOSH_MOD_ABI_VERSION \"{esc_abi}\"",
        f"#define DVARGOSH_MOD_BUILD_ID \"{esc_build_id}\"",
        f"#define DVARGOSH_MOD_BUILD_TIMESTAMP \"{esc_timestamp}\"",
        f"#define DVARGOSH_MOD_DOMAIN \"{esc_domain}\"",
        f"#define DVARGOSH_MOD_DOMAINS \"{esc_domains}\"",
        f"#define DVARGOSH_MOD_SECURED_KB {info['secured_memory_kb']}",
        f"#define DVARGOSH_MOD_PERMISSIONS_MASK {hex(info['permissions_mask'])}",
        f"#define DVARGOSH_MOD_DESCRIPTION \"{esc_desc}\"",
        f"#define DVARGOSH_MOD_AUTHOR \"{esc_author}\"",
        f"#define DVARGOSH_MOD_SERVICES_COUNT {svc_count}",
        f"#define DVARGOSH_MOD_SERVICES_SUMMARY \"{esc_services}\"",
        "",
        "extern \"C\" {",
        "#if defined(__GNUC__) || defined(__clang__)",
        "__attribute__((visibility(\"default\")))",
        "#endif",
        "extern const dvargosh::ModuleHeaderRaw dvargosh_module_header;",
        "",
        "#if defined(__GNUC__) || defined(__clang__)",
        "__attribute__((visibility(\"default\")))",
        "#endif",
        "const dvargosh::ModuleHeaderRaw* dvargosh_get_module_header();",
        "}",
        ""
    ]

    hpp_file.write_text("\n".join(hpp_lines))

    # 2. Generate _module_header.cpp
    cpp_lines = [
        "// Auto-generated by Dvargosh Meta Header Tool. DO NOT EDIT.",
        "#include \"_module_header.hpp\"",
        "#include \"dvargosh/module_header.hpp\"",
        "",
        "extern \"C\" {",
        "",
        "#if defined(__GNUC__) || defined(__clang__)",
        "__attribute__((visibility(\"default\")))",
        "#endif",
        "const dvargosh::ModuleHeaderRaw dvargosh_module_header = {",
        f"    {DVARGOSH_HEADER_MAGIC},",
        "    1,",
        "    static_cast<uint32_t>(sizeof(dvargosh::ModuleHeaderRaw)),",
        f"    \"{esc_name}\",",
        f"    \"{esc_version_str}\",",
        f"    {info['version_major']}, {info['version_minor']}, {info['version_patch']},",
        f"    \"{esc_abi}\",",
        f"    \"{esc_build_id}\",",
        f"    \"{esc_timestamp}\",",
        f"    \"{esc_compiler}\",",
        f"    \"{esc_domain}\",",
        f"    \"{esc_domains}\",",
        f"    {info['secured_memory_kb']},",
        f"    {hex(info['permissions_mask'])},",
        f"    \"{esc_desc}\",",
        f"    \"{esc_author}\",",
        f"    {svc_count},",
        f"    \"{esc_services}\",",
        "    0",
        "};",
        "",
        "#if defined(__GNUC__) || defined(__clang__)",
        "__attribute__((visibility(\"default\")))",
        "#endif",
        "const dvargosh::ModuleHeaderRaw* dvargosh_get_module_header() {",
        "    return &dvargosh_module_header;",
        "}",
        "",
        "} // extern \"C\"",
        ""
    ]

    cpp_file.write_text("\n".join(cpp_lines))

    # 3. Write JSON companion manifest
    meta_json = {
        "magic": "DVARGOSH_HEADER_V1",
        "name": info["name"],
        "version": info["version_str"],
        "version_major": info["version_major"],
        "version_minor": info["version_minor"],
        "version_patch": info["version_patch"],
        "abi_version": info["abi_version"],
        "build_id": info["build_id"],
        "build_timestamp": info["build_timestamp"],
        "compiler_info": info["compiler_info"],
        "domain": info["domain"],
        "supported_domains": info["supported_domains"],
        "secured_memory_kb": info["secured_memory_kb"],
        "permissions_mask": info["permissions_mask"],
        "permissions": info["permissions_list"],
        "description": info["description"],
        "author": info["author"],
        "services_count": svc_count,
        "services": svc_names
    }

    # Save to local module directory
    (folder / f"{info['name']}.meta.json").write_text(json.dumps(meta_json, indent=2))

    if out_meta_dir:
        out_meta_dir.mkdir(parents=True, exist_ok=True)
        json_file = out_meta_dir / f"{info['name']}.meta.json"
        json_file.write_text(json.dumps(meta_json, indent=2))
        # Also write candidate by folder name if distinct
        if folder.name != info["name"]:
            (out_meta_dir / f"{folder.name}.meta.json").write_text(json.dumps(meta_json, indent=2))

    return hpp_file, cpp_file

def find_all_module_dirs():
    dirs = []
    candidates = [MODULES_DIR, DEV_MODULES_DIR]
    seen = set()
    for base in candidates:
        if base.exists():
            for entry in base.iterdir():
                if entry.is_dir() and not entry.name.startswith("."):
                    if (entry / "module.def").exists() or list(entry.glob("*.cpp")):
                        resolved = entry.resolve()
                        if resolved not in seen:
                            seen.add(resolved)
                            dirs.append(entry)
    return dirs

def main():
    parser = argparse.ArgumentParser(description="Dvargosh Meta Header Pipeline Tool")
    parser.add_argument("--all", action="store_true", help="Process all discovered modules across directories")
    parser.add_argument("--module", type=str, help="Process a specific module folder path")
    parser.add_argument("--out-dir", type=str, default=str(BUILD_MODULES_DIR), help="Output directory for .meta.json manifests")
    parser.add_argument("--clean", action="store_true", help="Clean generated header files")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    out_dir = Path(args.out_dir)

    if args.module:
        target_dirs = [Path(args.module)]
    else:
        target_dirs = find_all_module_dirs()

    if args.clean:
        for d in target_dirs:
            for f in [d / "_module_header.hpp", d / "_module_header.cpp", d / f"{d.name}.meta.json"]:
                if f.exists():
                    f.unlink()
                    print(f"[dvargosh] Cleaned: {f}")
            for j in d.glob("*.meta.json"):
                if j.exists():
                    j.unlink()
                    print(f"[dvargosh] Cleaned: {j}")
        return

    print(f"[dvargosh] Meta Header Pipeline Tool: Processing {len(target_dirs)} module directories...")
    generated = 0
    for folder in target_dirs:
        info = read_module_info(folder)
        hpp, cpp = generate_header_files(info, out_dir)
        generated += 1
        if args.verbose or True:
            print(f"  * Generated metadata header for module '{info['name']}': {hpp.name}, {cpp.name} (Build: {info['build_id']})")

    print(f"[dvargosh] Successfully generated metadata headers and companion JSON manifests for {generated} modules.")

if __name__ == "__main__":
    main()
