#!/usr/bin/env python3
"""
Pipeline Dvargosh Generator:
- Scans both modules/ and development_modules/ (and staged build directories)
- Supports selectable module inclusion/exclusion via CLI (--select, --exclude)
- Parses attribution markers: DVARGOSH_SERVICE(dom), DVARGOSH_FN(dom), [[module:domain]]
- Auto-generates _generated_registration.cpp for native functions
- Auto-generates and updates module.def (domains, sources, link_libraries, auto_load)
- Generates strongly-typed C++ interface proxies for direct calling without invoke()
- Generates build/generated/src/pipeline_demo_app.cpp with AutoMapper and AutoLoader verification
- Generates modules/Modules.cmake and development_modules/DevModules.cmake
- Generates docs/dvargosh_schema.json (rich AST & custom linter metadata) and docs/dvargosh_lint.md
- Generates docs/architecture.md
"""

import os
import sys
import re
import argparse
import configparser
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT_DIR / "modules"
DEV_MODULES_DIR = ROOT_DIR / "development_modules"
BUILD_DIR = ROOT_DIR / "build"
DOCS_DIR = ROOT_DIR / "docs"
GENERATED_DIR = BUILD_DIR / "generated"
GENERATED_INCLUDE_DIR = GENERATED_DIR / "include" / "dvargosh" / "generated"
GENERATED_SRC_DIR = GENERATED_DIR / "src"

def scan_annotated_functions(folder: Path):
    """
    Scans C++ files in a directory for:
    1. Attribution markers: DVARGOSH_SERVICE(dom), DVARGOSH_FN(dom), [[module:domain]]
    2. Standard DVARGOSH_EXPORT_FN(name, domain, desc)
    """
    annotated = []
    exported = []

    attr_regex = re.compile(
        r'(?:DVARGOSH_SERVICE|DVARGOSH_FN)\s*\(\s*([a-zA-Z0-9_:\*]+)\s*\)|'
        r'\[\[\s*dvargosh::(?:service|fn)\s*\(\s*"([^"]+)"\s*\)\s*\]\]|'
        r'\[\[\s*([a-zA-Z0-9_]+:[a-zA-Z0-9_]+)\s*\]\]',
        re.MULTILINE
    )

    for cpp in folder.glob("*.cpp"):
        if cpp.name.startswith("_"):
            continue

        with open(cpp, "r", errors="ignore") as f:
            code = f.read()

        # 1. Check for DVARGOSH_EXPORT_FN and DVARGOSH_EXPORT_ALIAS_OVERRIDE
        exp_matches = re.findall(
            r'DVARGOSH_EXPORT_FN\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)',
            code
        )
        alias_matches = dict(re.findall(
            r'DVARGOSH_EXPORT_ALIAS_OVERRIDE\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*"([^"]+)"\s*\)',
            code
        ))
        req_args_matches = dict(re.findall(
            r'DVARGOSH_EXPORT_REQUIRED_ARGS\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([0-9]+)\s*\)',
            code
        ))
        for fn_name, domain, desc in exp_matches:
            alias = alias_matches.get(fn_name, "")
            req_args = int(req_args_matches.get(fn_name, 0))
            exported.append({
                "function": fn_name,
                "domain": domain,
                "description": desc,
                "source_file": cpp.name,
                "is_macro_export": True,
                "alias": alias,
                "required_args": req_args,
                "ret_type": "dvargosh::Value",
                "params": "const std::vector<dvargosh::Value>& args"
            })

        # 2. Check for attribution markers preceding native C++ functions
        for match in attr_regex.finditer(code):
            domain = match.group(1) or match.group(2) or match.group(3)
            after_pos = match.end()
            rest = code[after_pos:after_pos + 400]

            fn_match = re.search(
                r'^\s*([a-zA-Z0-9_:<>\s\*&]+?)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*\{',
                rest,
                re.MULTILINE
            )
            if fn_match:
                ret_type = fn_match.group(1).strip()
                fn_name = fn_match.group(2).strip()
                params = fn_match.group(3).strip()

                param_count = 0
                if params and params != "void":
                    param_count = len([p for p in params.split(",") if p.strip()])
                req_args = int(req_args_matches.get(fn_name, param_count))

                annotated.append({
                    "function": fn_name,
                    "domain": domain,
                    "description": f"Pipeline-attributed service method '{fn_name}'",
                    "source_file": cpp.name,
                    "ret_type": ret_type,
                    "params": params,
                    "required_args": req_args,
                    "is_macro_export": False
                })

    return annotated, exported

def get_module_name(folder: Path) -> str:
    name = folder.name
    def_file = folder / "module.def"
    if def_file.exists():
        cfg = configparser.ConfigParser()
        try:
            cfg.read(def_file)
            if "module" in cfg and "name" in cfg["module"]:
                name = cfg["module"]["name"]
        except Exception as e:
            print(f"[ERROR] Failed to parse {def_file}: {e}", file=sys.stderr)
            sys.exit(1)
    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"[ERROR] Invalid module name '{name}' in {folder}: must match ^[a-zA-Z0-9_]+$", file=sys.stderr)
        sys.exit(1)
    return name

def generate_registration_cpp(folder: Path, annotated_fns, reg_dir: Path = None):
    """
    Generates _generated_registration.cpp inside build/generated/registration/<module>/ to bridge native C++ functions
    to Dvargosh DVARGOSH_EXPORT_FN RPC registry, keeping source directories pristine.
    """
    if not annotated_fns:
        return None

    if reg_dir is None:
        reg_dir = GENERATED_DIR / "registration"

    mod_name = get_module_name(folder)
    mod_reg_dir = reg_dir / mod_name
    mod_reg_dir.mkdir(parents=True, exist_ok=True)
    reg_file = mod_reg_dir / "_generated_registration.cpp"

    lines = [
        "// Auto-generated by Dvargosh Pipeline Generator. DO NOT EDIT.",
        "#include \"dvargosh/dvargosh.hpp\"",
        "#include <string>",
        "",
        "namespace dvargosh {",
        ""
    ]

    for fn in annotated_fns:
        lines.append(f"extern {fn['ret_type']} {fn['function']}({fn['params']});")
    lines.append("")

    for fn in annotated_fns:
        lines.append(f"// Bridge for {fn['function']} (Domain: {fn['domain']})")
        lines.append(f"DVARGOSH_EXPORT_FN({fn['function']}, \"{fn['domain']}\", \"{fn['description']}\") {{")

        req_cnt = fn.get("required_args", 0)
        if req_cnt > 0:
            lines.append(f"    if (args.size() < {req_cnt}) {{")
            lines.append(f"        return Result<Value>::failure(StatusCode::InvalidArg, \"Method '{fn['function']}' requires at least {req_cnt} argument(s), but only \" + std::to_string(args.size()) + \" provided.\");")
            lines.append("    }")

        if "std::string" in fn["params"]:
            lines.append("    std::string arg0 = args.empty() ? \"\" : args[0].to_string();")
            lines.append(f"    auto res = {fn['function']}(arg0);")
            lines.append("    return Result<Value>::success(Value(res));")
        elif "double" in fn["params"]:
            lines.append("    double arg0 = args.empty() ? 0.0 : args[0].as_double();")
            lines.append("    double arg1 = args.size() > 1 ? args[1].as_double() : 0.0;")
            lines.append(f"    auto res = {fn['function']}(arg0, arg1);")
            lines.append("    return Result<Value>::success(Value(res));")
        elif not fn["params"] or fn["params"].strip() == "" or fn["params"].strip() == "void":
            lines.append("    (void)args;")
            lines.append(f"    auto res = {fn['function']}();")
            lines.append("    return Result<Value>::success(Value(res));")
        else:
            lines.append("    std::string arg0 = args.empty() ? \"\" : args[0].to_string();")
            lines.append(f"    auto res = {fn['function']}(arg0);")
            lines.append("    return Result<Value>::success(Value(res));")

        lines.append("}")

        # The alias (module.function) is the thing that the service is registered as.
        # The domain is omitted from the alias name for clean concise naming.
        alias = f"{mod_name}.{fn['function']}"
        lines.append(f"DVARGOSH_EXPORT_ALIAS_OVERRIDE({fn['function']}, \"{alias}\");")
        lines.append(f"DVARGOSH_EXPORT_REQUIRED_ARGS({fn['function']}, {req_cnt});\n")

    lines.append("} // namespace dvargosh\n")

    with open(reg_file, "w") as f:
        f.write("\n".join(lines))
    print(f"[dvargosh] Generated registration adapter: {reg_file.relative_to(ROOT_DIR)}")
    return reg_file

def sync_module_def(folder: Path, annotated_fns, exported_fns):
    def_file = folder / "module.def"
    name = folder.name

    all_sources = sorted([f.name for f in folder.glob("*.cpp") if not f.name.startswith("_")])

    domains_set = set()
    for fn in annotated_fns + exported_fns:
        if fn["domain"] != "*":
            domains_set.add(fn["domain"])
    domains_list = sorted(list(domains_set))
    domains_list.append("*")
    domains_str = ", ".join(domains_list)
    sources_str = ", ".join(all_sources)

    existing_name = name
    existing_desc = f"Auto-generated module definition for {name}"
    existing_author = "Dvargosh Dev Team"
    existing_kb = 2048

    if def_file.exists():
        cfg = configparser.ConfigParser()
        cfg.read(def_file)
        if "module" in cfg:
            existing_name = cfg["module"].get("name", existing_name)
            existing_desc = cfg["module"].get("description", existing_desc)
            existing_author = cfg["module"].get("author", existing_author)
            existing_kb = cfg["module"].getint("secured_memory_kb", existing_kb)

    if not re.match(r'^[a-zA-Z0-9_]+$', existing_name):
        print(f"[ERROR] Invalid module name '{existing_name}' in {def_file}: must match ^[a-zA-Z0-9_]+$", file=sys.stderr)
        sys.exit(1)

    content = f"""[module]
name = {existing_name}
version = 1.0.0
description = {existing_desc}
author = {existing_author}
secured_memory_kb = {existing_kb}
domains = {domains_str}
sources = {sources_str}
link_libraries = dvargosh_core
auto_load = true
"""

    # Sync module.def into build/modules/ ONLY (never overwrite source files)
    build_mod_dir = BUILD_DIR / "modules"
    build_mod_dir.mkdir(parents=True, exist_ok=True)
    with open(build_mod_dir / f"{existing_name}.def", "w") as f:
        f.write(content)
    with open(build_mod_dir / f"{folder.name}.def", "w") as f:
        f.write(content)

    print(f"[dvargosh] Synchronized manifest in build: build/modules/{existing_name}.def")

    return {
        "name": existing_name,
        "folder_name": folder.name,
        "version": "1.0.0",
        "description": existing_desc,
        "author": existing_author,
        "secured_memory_kb": existing_kb,
        "domains": domains_list,
        "sources": all_sources,
        "link_libraries": ["dvargosh_core"],
        "dir": folder,
        "exported_functions": annotated_fns + exported_fns
    }

def generate_typed_interfaces(all_modules):
    GENERATED_INCLUDE_DIR.mkdir(parents=True, exist_ok=True)

    for m in all_modules:
        if not m["exported_functions"]:
            continue

        mod_name = m["name"]
        folder_name = m["folder_name"]
        class_name = "".join(part.capitalize() for part in mod_name.split("_")) + "Proxy"
        header_file = GENERATED_INCLUDE_DIR / f"{folder_name}_interface.hpp"
        api_header_file = GENERATED_INCLUDE_DIR / f"{folder_name}_api.hpp"
        bind_header_file = GENERATED_INCLUDE_DIR / f"{folder_name}_bind.hpp"

        # 1. Generate Proxy Interface Header
        lines = [
            "#pragma once",
            "#include \"dvargosh/dvargosh.hpp\"",
            "#include <string>",
            "#include <stdexcept>",
            "",
            f"namespace dvargosh::generated::{folder_name} {{",
            "",
            f"/**",
            f" * @brief Auto-generated Strongly-Typed Proxy for '{mod_name}' module.",
            f" * Provides direct, compile-time typed C++ method call interfaces without manual invoke().",
            f" */",
            f"class {class_name} {{",
            "public:"
        ]

        for fn in m["exported_functions"]:
            fn_name = fn["function"]
            desc = fn["description"]
            if fn.get("alias"):
                svc_target = fn["alias"]
            elif fn.get("is_macro_export"):
                svc_target = fn_name
            else:
                svc_target = f"{mod_name}.{fn_name}"

            if "power" in fn_name or "calc" in fn_name:
                lines.append(f"    /** @brief {desc} */")
                lines.append(f"    static double {fn_name}(dvargosh::Registry& reg, double a, double b) {{")
                lines.append(f"        auto res = reg.invoke(\"{svc_target}\", {{dvargosh::Value(a), dvargosh::Value(b)}});")
                lines.append("        if (!res.is_ok()) throw std::runtime_error(\"Dvargosh RPC Error: \" + res.error_message());")
                lines.append("        return res.value().as_double();")
                lines.append("    }")
                lines.append(f"    static double {fn_name}(dvargosh::DIContainer& di, double a, double b) {{")
                lines.append(f"        return {fn_name}(*di.registry(), a, b);")
                lines.append("    }\n")
            elif not fn.get("params") or fn["params"].strip() == "":
                lines.append(f"    /** @brief {desc} */")
                lines.append(f"    static std::string {fn_name}(dvargosh::Registry& reg) {{")
                lines.append(f"        auto res = reg.invoke(\"{svc_target}\", {{}});")
                lines.append("        if (!res.is_ok()) throw std::runtime_error(\"Dvargosh RPC Error: \" + res.error_message());")
                lines.append("        return res.value().to_string();")
                lines.append("    }")
                lines.append(f"    static std::string {fn_name}(dvargosh::DIContainer& di) {{")
                lines.append(f"        return {fn_name}(*di.registry());")
                lines.append("    }\n")
            else:
                lines.append(f"    /** @brief {desc} */")
                lines.append(f"    static std::string {fn_name}(dvargosh::Registry& reg, const std::string& input) {{")
                lines.append(f"        auto res = reg.invoke(\"{svc_target}\", {{dvargosh::Value(input)}});")
                lines.append("        if (!res.is_ok()) throw std::runtime_error(\"Dvargosh RPC Error: \" + res.error_message());")
                lines.append("        return res.value().to_string();")
                lines.append("    }")
                lines.append(f"    static std::string {fn_name}(dvargosh::DIContainer& di, const std::string& input) {{")
                lines.append(f"        return {fn_name}(*di.registry(), input);")
                lines.append("    }\n")

        lines.append("};")
        lines.append(f"}} // namespace dvargosh::generated::{folder_name}\n")

        with open(header_file, "w") as f:
            f.write("\n".join(lines))
        print(f"[dvargosh] Generated typed proxy header: {header_file.name}")

        # 2. Generate Full Module API Header
        domains_cpp = ", ".join(f'"{d}"' for d in m["domains"])
        api_lines = [
            "#pragma once",
            "#include \"dvargosh/dvargosh.hpp\"",
            f"#include \"{folder_name}_interface.hpp\"",
            f"#include \"{folder_name}_bind.hpp\"",
            "#include <string>",
            "#include <vector>",
            "",
            f"namespace dvargosh::generated::{folder_name} {{",
            "",
            f"inline constexpr const char* MODULE_NAME = \"{mod_name}\";",
            f"inline constexpr const char* MODULE_VERSION = \"{m['version']}\";",
            f"inline constexpr size_t MODULE_SECURED_MEMORY_KB = {m['secured_memory_kb']};",
            "",
            f"inline const std::vector<std::string>& get_declared_domains() {{",
            f"    static const std::vector<std::string> s_domains = {{ {domains_cpp} }};",
            f"    return s_domains;",
            f"}}",
            "",
            f"}} // namespace dvargosh::generated::{folder_name}\n"
        ]
        with open(api_header_file, "w") as f:
            f.write("\n".join(api_lines))
        print(f"[dvargosh] Generated API header: {api_header_file.name}")

        # 3. Generate AutoMapper Binder Header
        bind_lines = [
            "#pragma once",
            "#include \"dvargosh/dvargosh.hpp\"",
            "#include \"dvargosh/auto_mapper.hpp\"",
            "#include <functional>",
            "#include <memory>",
            "#include <string>",
            "",
            f"namespace dvargosh::generated::{folder_name} {{",
            "",
            f"/**",
            f" * @brief Auto-generated typed binder for '{mod_name}' using AutoMapper.",
            f" */",
            f"struct Binder {{",
        ]

        for fn in m["exported_functions"]:
            fn_name = fn["function"]
            if "power" in fn_name or "calc" in fn_name:
                bind_lines.append(f"    std::function<double(double, double)> {fn_name};")
            elif not fn.get("params") or fn["params"].strip() == "":
                bind_lines.append(f"    std::function<std::string()> {fn_name};")
            else:
                bind_lines.append(f"    std::function<std::string(const std::string&)> {fn_name};")

        bind_lines.append("")
        bind_lines.append("    static Binder bind(std::shared_ptr<dvargosh::DIContainer> di) {")
        bind_lines.append("        dvargosh::AutoMapper mapper(di);")
        bind_lines.append("        return bind(mapper);")
        bind_lines.append("    }")
        bind_lines.append("")
        bind_lines.append("    static Binder bind(dvargosh::AutoMapper& mapper) {")
        bind_lines.append("        Binder b;")
        for fn in m["exported_functions"]:
            fn_name = fn["function"]
            if fn.get("alias"):
                svc_target = fn["alias"]
            elif fn.get("is_macro_export"):
                svc_target = fn_name
            else:
                svc_target = f"{mod_name}.{fn_name}"
            if "power" in fn_name or "calc" in fn_name:
                bind_lines.append(f"        if (mapper.has_service(\"{svc_target}\")) {{")
                bind_lines.append(f"            b.{fn_name} = mapper.bind<double, double, double>(\"{svc_target}\");")
                bind_lines.append("        }")
            elif not fn.get("params") or fn["params"].strip() == "":
                bind_lines.append(f"        if (mapper.has_service(\"{svc_target}\")) {{")
                bind_lines.append(f"            b.{fn_name} = mapper.bind<std::string>(\"{svc_target}\");")
                bind_lines.append("        }")
            else:
                bind_lines.append(f"        if (mapper.has_service(\"{svc_target}\")) {{")
                bind_lines.append(f"            b.{fn_name} = mapper.bind<std::string, const std::string&>(\"{svc_target}\");")
                bind_lines.append("        }")
        bind_lines.append("        return b;")
        bind_lines.append("    }")
        bind_lines.append("};")
        bind_lines.append(f"}} // namespace dvargosh::generated::{folder_name}\n")

        with open(bind_header_file, "w") as f:
            f.write("\n".join(bind_lines))
        print(f"[dvargosh] Generated binder header: {bind_header_file.name}")

def generate_pipeline_demo_app():
    GENERATED_SRC_DIR.mkdir(parents=True, exist_ok=True)
    app_file = GENERATED_SRC_DIR / "pipeline_demo_app.cpp"

    content = """// Auto-generated by Dvargosh Pipeline Generator. DO NOT EDIT.
#include "dvargosh/dvargosh.hpp"
#include "dvargosh/generated/crypto_accelerator_interface.hpp"
#include "dvargosh/generated/crypto_accelerator_api.hpp"
#include "dvargosh/generated/crypto_accelerator_bind.hpp"
#include "dvargosh/generated/demo_pkg_interface.hpp"
#include "dvargosh/generated/demo_pkg_api.hpp"
#include "dvargosh/generated/demo_pkg_bind.hpp"
#if __has_include("dvargosh/generated/helloWorld_interface.hpp")
#include "dvargosh/generated/helloWorld_interface.hpp"
#include "dvargosh/generated/helloWorld_api.hpp"
#include "dvargosh/generated/helloWorld_bind.hpp"
#endif
#if __has_include("dvargosh/generated/telecom_interface.hpp")
#include "dvargosh/generated/telecom_interface.hpp"
#include "dvargosh/generated/telecom_api.hpp"
#include "dvargosh/generated/telecom_bind.hpp"
#endif
#include <cstdlib>
#include <iostream>
#include <cassert>

using namespace dvargosh;
using namespace dvargosh::generated::crypto_accelerator;
using namespace dvargosh::generated::demo_pkg;
#if __has_include("dvargosh/generated/helloWorld_interface.hpp")
using namespace dvargosh::generated::helloWorld;
#endif
#if __has_include("dvargosh/generated/telecom_interface.hpp")
using namespace dvargosh::generated::telecom;
#endif

int main() {
    std::cout << "[dvargosh] Pipeline Auto-Generated App Demo\\n";

    ScopedCallFrame host_frame("host_pipeline_app", "system");
    auto di = std::make_shared<DIContainer>();
    // Signing key comes from the environment; unsigned dev mode falls back to verification-free loading.
    const char* env_key = std::getenv("DVARGOSH_SIGNING_KEY");
    const std::string secret_key = env_key ? std::string(env_key) : std::string();

    ModuleLoaderConfig cfg;
    cfg.enforce_signatures = !secret_key.empty();
    cfg.secret_signing_key = secret_key;
    ModuleLoader loader(di, cfg);
    if (secret_key.empty()) {
        std::cout << "[SECURITY] DVARGOSH_SIGNING_KEY not set — unsigned development mode (signature verification DISABLED).\\n";
    }

    loader.add_search_path("./build/modules");
    loader.add_search_path("./build/development_modules");
    loader.add_search_path("./modules");
    loader.add_search_path("./development_modules");
    loader.add_search_path("../build/modules");
    loader.add_search_path("../build/development_modules");

    // Discover modules via dynamic symbol inspection
    auto discovered = loader.discover_all_modules();
    std::cout << "[Pipeline App] Discovered " << discovered.size() << " modules via symbol metadata.\\n";

    // 1. Test Enhanced AutoLoader: auto_load_matching & auto_load_domain
    std::cout << "\\n[Pipeline App] Testing Enhanced C++ AutoLoader APIs...\\n";
    auto match_res = loader.auto_load_matching("demo_*", secret_key);
    assert(match_res.is_ok());
    std::cout << "  ✓ auto_load_matching('demo_*') loaded " << match_res.value() << " modules.\\n";

    auto dom_res = loader.auto_load_domain("accelerator:hash", secret_key);
    assert(dom_res.is_ok());
    std::cout << "  ✓ auto_load_domain('accelerator:hash') successfully loaded provider module.\\n";

    // Load remaining modules
    auto sign_and_load = [&](const std::string& name) {
        auto file_res = loader.find_module_file(name);
        if (!file_res.is_ok()) return;
        auto sig_res = Crypto::sign_file(secret_key, file_res.value());
        std::string sig = sig_res.is_ok() ? sig_res.value() : "";
        loader.load(name, sig);
    };

    sign_and_load("hello_world");
    sign_and_load("telecom");

    std::cout << "\\n[Pipeline App] Calling auto-generated typed interfaces directly (No invoke() needed):\\n";

    // 2. Direct typed call to DemoPkgProxy
    std::string vault_hash = DemoPkgProxy::demo_pkg_vault_hash(*di, "PipelineSecureData");
    std::cout << "  * DemoPkgProxy::demo_pkg_vault_hash -> " << vault_hash << "\\n";
    assert(!vault_hash.empty());

    double power_val = DemoPkgProxy::demo_pkg_worker_power(*di, 3.0, 4.0);
    std::cout << "  * DemoPkgProxy::demo_pkg_worker_power(3, 4) -> " << power_val << "\\n";
    assert(power_val == 81.0);

    // 3. Direct typed call to CryptoAcceleratorProxy
    std::string accel_hash = CryptoAcceleratorProxy::accelerator_sha256(*di, "DirectCallPayload");
    std::cout << "  * CryptoAcceleratorProxy::accelerator_sha256 -> " << accel_hash << "\\n";
    assert(accel_hash.rfind("ACCEL_HASH_", 0) == 0);

    std::string rot13_txt = CryptoAcceleratorProxy::accelerator_rot13(*di, "PipelineRocks");
    std::cout << "  * CryptoAcceleratorProxy::accelerator_rot13 -> " << rot13_txt << "\\n";
    assert(rot13_txt == "CvcryvarEbmxf");

#if __has_include("dvargosh/generated/helloWorld_interface.hpp")
    std::string hw_res = HelloWorldProxy::hello_world(*di, "Developer");
    std::cout << "  * HelloWorldProxy::hello_world -> " << hw_res << "\\n";
    assert(hw_res == "HELLO_WORLD_Developer");

    std::string vault_key = HelloWorldProxy::get_safe_vault_key(*di);
    std::cout << "  * HelloWorldProxy::get_safe_vault_key -> " << vault_key << "\\n";
    assert(vault_key.find("SECURE_KEY_NAM_CAPTIVES") != std::string::npos);

    std::string intruder_space = HelloWorldProxy::intruder_access_safe_space(*di);
    std::cout << "  * HelloWorldProxy::intruder_access_safe_space -> " << intruder_space << "\\n";
    assert(intruder_space.rfind("REJECTED:", 0) == 0);

    std::string intruder_rpc = HelloWorldProxy::intruder_invoke_vault(*di);
    std::cout << "  * HelloWorldProxy::intruder_invoke_vault -> " << intruder_rpc << "\\n";
    assert(intruder_rpc.rfind("REJECTED:", 0) == 0);

    std::string others = HelloWorldProxy::invokeothers(*di);
    std::cout << "  * HelloWorldProxy::invokeothers -> " << others << "\\n";
    assert(!others.empty() && others.find("Error") == std::string::npos);
#endif

#if __has_include("dvargosh/generated/telecom_interface.hpp")
    std::string telecom_res = TelecomProxy::telecom_echo(*di, "PacketHeader");
    std::cout << "  * TelecomProxy::telecom_echo -> " << telecom_res << "\\n";
    assert(telecom_res == "[telecom] PacketHeader");
#endif

    // 4. Test C++ AutoMapper: Bind dynamic RPC method to standard std::function
    std::cout << "\\n[Pipeline App] Testing C++ AutoMapper Reflection & Binding...\\n";
    AutoMapper mapper(di);
    assert(mapper.has_service("demo_pkg.demo_pkg_vault_hash"));
    std::cout << "  * AutoMapper: Found domain for 'demo_pkg.demo_pkg_vault_hash': "
              << mapper.find_domain_for_service("demo_pkg.demo_pkg_vault_hash") << "\\n";

    auto bound_hash = mapper.bind<std::string, const std::string&>("demo_pkg.demo_pkg_vault_hash");
    std::string mapper_out = bound_hash("BoundViaAutoMapper");
    std::cout << "  * AutoMapper::bind callable result -> " << mapper_out << "\\n";
    assert(!mapper_out.empty());

    // 5. Test Auto-Generated Binder headers (_bind.hpp)
    std::cout << "\\n[Pipeline App] Testing Auto-Generated Binder headers (_bind.hpp)...\\n";
    auto demo_binder = dvargosh::generated::demo_pkg::Binder::bind(di);
    std::string bound_vault = demo_binder.demo_pkg_vault_hash("BinderPayload");
    std::cout << "  * demo_binder.demo_pkg_vault_hash -> " << bound_vault << "\\n";
    assert(!bound_vault.empty());

    double bound_power = demo_binder.demo_pkg_worker_power(2.0, 5.0);
    std::cout << "  * demo_binder.demo_pkg_worker_power(2, 5) -> " << bound_power << "\\n";
    assert(bound_power == 32.0);

    auto crypto_binder = dvargosh::generated::crypto_accelerator::Binder::bind(di);
    std::string bound_sha = crypto_binder.accelerator_sha256("BinderCryptoPayload");
    std::cout << "  * crypto_binder.accelerator_sha256 -> " << bound_sha << "\\n";
    assert(!bound_sha.empty());

    // 6. Test Module API constants (_api.hpp)
    assert(std::string(dvargosh::generated::demo_pkg::MODULE_NAME) == "demo_pkg");
    assert(std::string(dvargosh::generated::crypto_accelerator::MODULE_NAME) == "crypto_accelerator");

    std::cout << "\\n[dvargosh] All pipeline direct typed calls & binders verified successfully.\\n";
    return 0;
}
"""
    with open(app_file, "w") as f:
        f.write(content)
    print(f"[dvargosh] Generated pipeline demo application: {app_file.name}")

def generate_cmake_file(modules, output_file: Path, output_subdir: str):
    lines = [
        f"# Auto-generated by pipeline_dvargosh/generator.py for {output_subdir}",
        "# DO NOT EDIT MANUALLY\n",
        f"set(DVARGOSH_{output_subdir.upper()}_TARGETS \"\")\n"
    ]
    for m in modules:
        target_name = f"mod_{m['folder_name']}"
        source_paths = []
        for src in m["sources"]:
            full_src = m["dir"] / src
            try:
                rel = full_src.relative_to(ROOT_DIR)
                source_paths.append(f"${{CMAKE_CURRENT_SOURCE_DIR}}/{rel}")
            except ValueError:
                try:
                    rel = full_src.relative_to(BUILD_DIR)
                    source_paths.append(f"${{CMAKE_BINARY_DIR}}/{rel}")
                except ValueError:
                    source_paths.append(str(full_src))
        sources_str = " ".join(source_paths)
        links_str = " ".join(m["link_libraries"])

        try:
            rel_inc = m["dir"].relative_to(ROOT_DIR)
            inc_dir = f"${{CMAKE_CURRENT_SOURCE_DIR}}/{rel_inc}"
        except ValueError:
            try:
                rel_inc = m["dir"].relative_to(BUILD_DIR)
                inc_dir = f"${{CMAKE_BINARY_DIR}}/{rel_inc}"
            except ValueError:
                inc_dir = str(m["dir"])

        lines.append(f"# Module: {m['name']} (Domains: {', '.join(m['domains'])})")

        # Check for generated registration bridge in build/generated/registration/<name>
        reg_file = BUILD_DIR / "generated" / "registration" / m["name"] / "_generated_registration.cpp"
        if reg_file.exists():
            source_paths.append(f"${{CMAKE_BINARY_DIR}}/generated/registration/{m['name']}/_generated_registration.cpp")

        # Check for generated module header cpp in build/generated/headers/<name>
        hdr_file = BUILD_DIR / "generated" / "headers" / m["name"] / "_module_header.cpp"
        if hdr_file.exists():
            source_paths.append(f"${{CMAKE_BINARY_DIR}}/generated/headers/{m['name']}/_module_header.cpp")

        sources_str = " ".join(source_paths)
        links_str = " ".join(m["link_libraries"])

        try:
            rel_inc = m["dir"].relative_to(ROOT_DIR)
            inc_dir = f"${{CMAKE_CURRENT_SOURCE_DIR}}/{rel_inc}"
        except ValueError:
            try:
                rel_inc = m["dir"].relative_to(BUILD_DIR)
                inc_dir = f"${{CMAKE_BINARY_DIR}}/{rel_inc}"
            except ValueError:
                inc_dir = str(m["dir"])

        lines.append(f"add_library({target_name} SHARED {sources_str})")
        lines.append(f"target_link_libraries({target_name} PRIVATE {links_str})")
        lines.append(f"target_include_directories({target_name} PRIVATE include {inc_dir} ${{CMAKE_BINARY_DIR}}/generated/headers/{m['name']} ${{CMAKE_BINARY_DIR}}/generated/registration/{m['name']} ${{CMAKE_BINARY_DIR}}/generated/include)")
        lines.append(f"set_target_properties({target_name} PROPERTIES")
        lines.append(f"    PREFIX \"lib\"")
        lines.append(f"    LIBRARY_OUTPUT_DIRECTORY ${{CMAKE_BINARY_DIR}}/{output_subdir}")
        lines.append(")")
        lines.append(f"list(APPEND DVARGOSH_{output_subdir.upper()}_TARGETS {target_name})\n")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(lines))
    print(f"[dvargosh] Generated cmake config: {output_file.name}")

def generate_introspection_docs(all_modules):
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    # Detailed Enterprise JSON Schema designed for custom linting tooling
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "DvargoshModuleRegistrySchema",
        "description": "Comprehensive AST metadata and lint specification for Dvargosh modules, domains, and exported services.",
        "version": "1.0.0",
        "generated_by": "pipeline_dvargosh/generator.py",
        "lint_rules": [
            {
                "id": "DVARGOSH_LINT_001",
                "name": "DomainNamingConvention",
                "severity": "error",
                "description": "Domain tags must follow <module_name>:<subsystem> or wildcard '*'.",
                "regex": r"^([a-zA-Z0-9_]+:[a-zA-Z0-9_\*]+|\*)$"
            },
            {
                "id": "DVARGOSH_LINT_002",
                "name": "SecuredMemoryGuardCheck",
                "severity": "warning",
                "description": "Hardware-guarded secured memory space must not exceed 64 MB (65536 KB) per module without elevated quota.",
                "max_kb": 65536
            },
            {
                "id": "DVARGOSH_LINT_003",
                "name": "SignatureVerificationEnforced",
                "severity": "error",
                "description": "All dynamic shared library modules must be cryptographically signed via HMAC-SHA256 prior to loading."
            },
            {
                "id": "DVARGOSH_LINT_004",
                "name": "TypeSafeProxyAvailability",
                "severity": "info",
                "description": "Every exported DVARGOSH_SERVICE function should have an auto-generated strongly-typed proxy wrapper."
            }
        ],
        "modules": []
    }

    markdown = [
        "# Dvargosh Module Schema & Introspection Documentation\n",
        "Auto-generated by `/pipeline_dvargosh/generator.py` for API introspection, verification, and linting.\n",
        "## Summary of Modules and Subsystems\n"
    ]

    for m in all_modules:
        mod_entry = {
            "name": m["name"],
            "folder_name": m["folder_name"],
            "version": m["version"],
            "description": m["description"],
            "author": m["author"],
            "secured_memory_kb": m["secured_memory_kb"],
            "domains": m["domains"],
            "sources": m["sources"],
            "services": []
        }

        markdown.append(f"### Module: `{m['name']}` (v{m['version']})")
        markdown.append(f"- **Description**: {m['description']}")
        markdown.append(f"- **Domains (Subsystems)**: {', '.join(m['domains'])}")
        markdown.append(f"- **Secured Memory Quota**: {m['secured_memory_kb']} KB")
        markdown.append(f"- **How to Load**:\n  ```cpp\n  loader.load(\"{m['name']}\", signature);\n  ```")

        proxy_cls = "".join(part.capitalize() for part in m["name"].split("_")) + "Proxy"
        if m["exported_functions"]:
            markdown.append("\n**Exported Functions & Invocation Syntax**:")
            markdown.append("| Function Name | Domain | Description | Dynamic RPC Syntax | Direct Typed Proxy Syntax |")
            markdown.append("| :--- | :--- | :--- | :--- | :--- |")

            for fn in m["exported_functions"]:
                fn_name = fn["function"]
                dom = fn["domain"]
                desc = fn["description"]
                rpc_call = f'`registry->invoke("{fn_name}", {{...}})`'
                proxy_call = f'`{proxy_cls}::{fn_name}(ctx, ...)`'
                automapper_call = f'`mapper.bind<ReturnType, ArgTypes...>("{fn_name}")`'

                # Rich tooltip for IDE hover
                hover_text = (
                    f"### Dvargosh Service: `{fn_name}`\n"
                    f"* **Domain**: `{dom}`\n"
                    f"* **Description**: {desc}\n"
                    f"* **RPC Invocation**:\n```cpp\nctx.registry()->invoke(\"{fn_name}\", {{args}});\n```\n"
                    f"* **Direct Typed Call**:\n```cpp\n{proxy_cls}::{fn_name}(ctx, args);\n```\n"
                    f"* **AutoMapper Binding**:\n```cpp\nauto fn = mapper.bind<ReturnType, ...>(\"{fn_name}\");\n```\n"
                )

                service_entry = {
                    "name": fn_name,
                    "domain": dom,
                    "description": desc,
                    "source_file": fn["source_file"],
                    "signature": f"{fn['ret_type']} {fn_name}({fn['params']})",
                    "return_type": fn["ret_type"],
                    "parameters": fn["params"],
                    "security": {
                        "required_permissions": ["DynamicInvoke"],
                        "scoped_domain_enforcement": True
                    },
                    "rpc_syntax": rpc_call,
                    "typed_proxy_syntax": proxy_call,
                    "automapper_syntax": automapper_call,
                    "hover_tooltip": hover_text
                }
                mod_entry["services"].append(service_entry)
                markdown.append(f"| `{fn_name}` | `{dom}` | {desc} | {rpc_call} | {proxy_call} |")

        schema["modules"].append(mod_entry)
        markdown.append("\n---\n")

    with open(BUILD_DIR / "schema.json", "w") as f:
        json.dump(schema, f, indent=2)
    with open(GENERATED_DIR / "schema.json", "w") as f:
        json.dump(schema, f, indent=2)
    with open(DOCS_DIR / "dvargosh_schema.json", "w") as f:
        json.dump(schema, f, indent=2)
    print(f"[dvargosh] Generated Schema: {BUILD_DIR / 'schema.json'}")

    with open(DOCS_DIR / "dvargosh_lint.md", "w") as f:
        f.write("\n".join(markdown))
    print(f"[dvargosh] Generated Lint Docs: {DOCS_DIR / 'dvargosh_lint.md'}")

def generate_architecture_doc():
    doc_path = DOCS_DIR / "architecture.md"
    content = """# Dvargosh Architectural Blueprint

This document details the architectural principles, containerization mechanisms, dynamic linking lifecycle, and code generation pipelines of the **Dvargosh Runtime Engine**.

---

## 1. Core Architectural Paradigm: Packages, Subsystems & Services

Dvargosh decouples software into a 3-tier hierarchy:
1. **Module (Package)**: The complete independently compiled and signed dynamic shared object (`.dylib` / `.so`). A module manages its own binary lifecycle (`on_load`, `on_start`, `on_stop`, `on_unload`), memory quota, and permission manifest.
2. **Domain (Subsystem)**: A logical subsystem or boundary partition within a module (e.g. `demo_pkg:vault`, `accelerator:hash`, `core:logger`). Domains enforce intra-module and inter-module isolation.
3. **Service (Function)**: Individual functional capabilities exposed by a domain. Services can be invoked dynamically via RPC (`registry->invoke()`) or called with direct compile-time type safety via auto-generated typed proxies (`Proxy::method()`).

```
+-------------------------------------------------------------------------+
|                              MODULE (PKG)                               |
|  [Hardware Guarded Memory Space: mmap + PROT_NONE + volatile scrub]    |
|                                                                         |
|  +----------------------------+     +--------------------------------+  |
|  |     DOMAIN: <pkg>:vault    |     |      DOMAIN: <pkg>:worker      |  |
|  |  +-----------------------+ |     |  +---------------------------+ |  |
|  |  | Service: hash_secret  | |     |  | Service: compute_power    | |  |
|  |  +-----------------------+ |     |  +---------------------------+ |  |
|  +----------------------------+     +--------------------------------+  |
|                ▲                                   ▲                    |
|                └───────────── SCOPED '*' ──────────┘                    |
|                         (Package Orchestrator)                          |
+-------------------------------------------------------------------------+
```

### Scoped Wildcard (`<module>.*`)
The wildcard domain `*` is strictly scoped per module (`demo_pkg.*`). Orchestrator services registered under `*` can cross subsystem boundaries inside their own package, while preventing unauthorized cross-module leaks.

---

## 2. In-Process Memory Containerization & Hardware Guarding

To ensure zero cross-module memory contamination without the latency of IPC / process boundaries:
1. **Hardware Guard Pages**: Each module's secured memory container is allocated via `mmap()` surrounded by leading and trailing `PROT_NONE` guard pages. Any out-of-bounds read or write immediately raises a hardware `SIGSEGV` trap.
2. **Page Pinning (`mlock`)**: Critical memory regions are pinned in physical RAM to prevent swapping sensitive cryptographic key material to swap partitions.
3. **Volatile Scrubbing**: Upon deallocation or module unloading, allocated memory blocks are wiped using volatile zeroing (`explicit_bzero` / volatile loop) to defeat cold-boot attacks and dangling memory inspection.

---

## 3. Dynamic Module Loading Lifecycle & Security Verification

Modules undergo a strict 6-stage lifecycle:

```
[Discovery] ──► [Header Magic Check] ──► [HMAC-SHA256 Sig Check] ──► [dlopen(RTLD_LOCAL)] ──► [on_load / on_start] ──► [Active]
                                                                                                                        │
[Terminated] ◄── [dlclose] ◄── [Domain Detachment & Scrub] ◄── [on_stop / on_unload] ◄──────────────────────────────────┘
```

1. **Auto-Discovery**: `discover_all_modules()` scans search directories for `.dylib` / `.so` binaries.
2. **Binary Header Introspection**: Before running any initialization code, the loader resolves exported constant symbols:
   - `dvargosh_module_magic`: Must match `0xD7A29054`.
   - `dvargosh_module_name`: Verifies package identity.
   - `dvargosh_build_id` & `dvargosh_abi_version`: Ensures ABI compatibility.
3. **Cryptographic Signature Verification**: The loader validates the binary HMAC-SHA256 signature using constant-time comparison. Unsigned or tampered binaries are immediately rejected with `StatusCode::SignatureInvalid`.
4. **Isolated Dynamic Linking**: Dynamically loaded via `dlopen(path, RTLD_NOW | RTLD_LOCAL)` to keep symbols private to the module.
5. **Auto-Registration**: Non-monolithic exported functions self-register into their respective domains without monolithic `on_load()` boilerplate.
6. **Graceful Decommissioning**: During `unload_module()`, services are unregistered, domains are unplugged, and secured spaces are scrubbed before `dlclose()`.

---

## 4. Dual Calling Modes: Dynamic RPC vs Direct Typed Proxies

### Why C++ `[[...]]` Alone Cannot Register Functions at Runtime
In C++17, compiler attributes (`[[...]]`) are strictly compile-time metadata. Standard C++ has no native runtime reflection engine (unlike Java or C#). Standard attributes emit zero machine code and cannot trigger registration upon library loading.

Dvargosh bridges this gap with its **Pipeline Code Generator**:
1. Developers decorate clean C++ native functions with `DVARGOSH_SERVICE(module:domain)`.
2. At C++ compile time, the preprocessor expands `DVARGOSH_SERVICE` to a harmless annotation or comments it out, leaving clean, standard C++ code.
3. The `pipeline_dvargosh` scanner parses the decorated functions and automatically synthesizes:
   - Registration bridges (`_generated_registration.cpp`) with `DVARGOSH_EXPORT_FN`.
   - Strongly-typed C++ interface headers (`<module>_interface.hpp`) with typed proxy classes.
   - Auto-generated binders (`<module>_bind.hpp`) and module constants (`<module>_api.hpp`).

### Direct Typed Calling Syntax
Callers include the generated interface and execute direct calls:
```cpp
// Direct typed call (no manual registry->invoke() or Value boxing):
std::string hash = CryptoAcceleratorProxy::accelerator_sha256(ctx, "SecretPayload");
double result = DemoPkgProxy::demo_pkg_worker_power(ctx, 2.0, 8.0);
```

### Dynamic RPC with Fuzzy Suggestions
Callers without compile-time headers use dynamic RPC. If a method is misspelled, the registry calculates Levenshtein distance and suggests the closest match:
```cpp
ctx.registry()->invoke("demo_pkg_worker_pow", {2.0, 8.0});
// Error: Method 'demo_pkg_worker_pow' not found. Did you mean 'demo_pkg_worker_power'?
```
"""
    with open(doc_path, "w") as f:
        f.write(content)
    print(f"[dvargosh] Generated Architecture Docs: {doc_path.name}")

def process_module_dir(folder: Path):
    cpp_files = [f for f in folder.glob("*.cpp")]
    if not cpp_files:
        return None
    annotated_fns, exported_fns = scan_annotated_functions(folder)
    generate_registration_cpp(folder, annotated_fns)
    return sync_module_def(folder, annotated_fns, exported_fns)

def parse_args():
    parser = argparse.ArgumentParser(description="Dvargosh Pipeline Generator")
    parser.add_argument("--select", help="Comma-separated module names to include (e.g. math,logger,crypto_accelerator)")
    parser.add_argument("--exclude", help="Comma-separated module names to exclude")
    return parser.parse_args()

def main():
    args = parse_args()
    selected_mods = [s.strip() for s in args.select.split(",")] if args.select else None
    excluded_mods = [s.strip() for s in args.exclude.split(",")] if args.exclude else []

    print("[dvargosh] Running Pipeline Generator...")

    # Helper filter
    def is_selected(name, folder_name):
        if name in excluded_mods or folder_name in excluded_mods:
            return False
        if selected_mods is not None:
            return name in selected_mods or folder_name in selected_mods
        return True

    # 1. Process standard modules
    std_modules = []
    if MODULES_DIR.exists():
        for item in sorted(MODULES_DIR.iterdir()):
            if item.is_dir() and item.name != "CMakeFiles" and not item.name.startswith("."):
                mod = process_module_dir(item)
                if mod and is_selected(mod["name"], mod["folder_name"]):
                    std_modules.append(mod)
        if std_modules:
            generate_cmake_file(std_modules, GENERATED_DIR / "Modules.cmake", "modules")

    # 2. Process development modules
    dev_modules = []
    target_dev_dir = BUILD_DIR / "development_modules"
    if DEV_MODULES_DIR.exists():
        # Re-stage from scratch: copytree with dirs_exist_ok would let stale module
        # dirs (renames, removed experiments) survive forever and pollute the schema.
        import shutil
        if target_dev_dir.exists():
            shutil.rmtree(target_dev_dir, ignore_errors=True)
        shutil.copytree(DEV_MODULES_DIR, target_dev_dir)

    if target_dev_dir.exists():
        for item in sorted(target_dev_dir.iterdir()):
            if item.is_dir() and item.name != "CMakeFiles" and not item.name.startswith("."):
                mod = process_module_dir(item)
                if mod and is_selected(mod["name"], mod["folder_name"]):
                    dev_modules.append(mod)

        if dev_modules:
            generate_cmake_file(dev_modules, GENERATED_DIR / "DevModules.cmake", "development_modules")

    # Clean any stray cmake or generated artifacts in source directories
    for stray in [MODULES_DIR / "Modules.cmake", DEV_MODULES_DIR / "DevModules.cmake"]:
        if stray.exists():
            try:
                stray.unlink()
            except Exception:
                pass

    # 3. Generate typed interfaces, APIs, and binders
    all_modules = std_modules + dev_modules
    generate_typed_interfaces(all_modules)

    # 4. Generate pipeline demo app
    generate_pipeline_demo_app()

    # 5. Generate documentation, lint schema, and architecture documentation
    generate_introspection_docs(all_modules)
    generate_architecture_doc()

    print("[dvargosh] Pipeline code generation complete.")

if __name__ == "__main__":
    main()
