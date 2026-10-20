#!/usr/bin/env python3
"""
Dvargosh First-Time Setup & Diagnostic Wizard
Validates host environment, compilers, CMake version, and toolchain configurations.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Add pipeline directory to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import ui

def check_command(cmd, min_version=None):
    path = shutil.which(cmd)
    if not path:
        return False, "Not found"
    try:
        out = subprocess.check_output([cmd, "--version"], stderr=subprocess.STDOUT, universal_newlines=True)
        first_line = out.splitlines()[0] if out.splitlines() else "Available"
        return True, first_line
    except Exception as e:
        return True, f"Found at {path} ({e})"

def main():
    ui.print_banner("DVARGOSH RUNTIME ENGINE", "First-Time Environment Setup & Toolchain Diagnostic")

    ui.print_step(1, 4, "Checking System Toolchain & Prerequisites")
    tools = [
        ("C++ Compiler (clang++)", "clang++"),
        ("C++ Compiler (g++)", "g++"),
        ("Build System (cmake)", "cmake"),
        ("Task Runner (make)", "make"),
        ("Python Runtime (python3)", "python3"),
        ("Git Version Control", "git")
    ]

    table_rows = []
    has_cxx = False
    has_cmake = False

    for name, bin_name in tools:
        found, details = check_command(bin_name)
        status = f"✓ {details[:40]}" if found else "✗ Missing"
        table_rows.append([name, status])
        if found and bin_name in ("clang++", "g++"):
            has_cxx = True
        if found and bin_name == "cmake":
            has_cmake = True

    ui.print_table("Prerequisite Diagnostics", ["Component", "Status / Version"], table_rows)

    if not has_cxx:
        ui.print_error("No supported C++ compiler (clang++ or g++) found on PATH.")
        sys.exit(1)
    if not has_cmake:
        ui.print_error("CMake 3.16+ is required but was not found.")
        sys.exit(1)

    ui.print_step(2, 4, "Verifying Repository Layout & Staging")
    required_dirs = [
        ROOT_DIR / "include" / "dvargosh",
        ROOT_DIR / "src" / "core",
        ROOT_DIR / "modules",
        ROOT_DIR / "development_modules",
        ROOT_DIR / "pipeline_dvargosh",
        ROOT_DIR / "docs"
    ]
    for d in required_dirs:
        d.mkdir(parents=True, exist_ok=True)
        ui.print_success(f"Directory ready: {d.relative_to(ROOT_DIR)}")

    ui.print_step(3, 4, "Initializing Build & Generated Cache Directories")
    (ROOT_DIR / "build" / "generated" / "include" / "dvargosh" / "generated").mkdir(parents=True, exist_ok=True)
    (ROOT_DIR / "build" / "generated" / "src").mkdir(parents=True, exist_ok=True)
    (ROOT_DIR / "build" / "development_modules").mkdir(parents=True, exist_ok=True)
    (ROOT_DIR / "dist").mkdir(parents=True, exist_ok=True)
    ui.print_success("Build cache & staging directories initialized.")

    ui.print_step(4, 4, "Checking Python Dependencies")
    if ui._HAS_RICH:
        ui.print_success("Python 'rich' UI library is active and enabled.")
    else:
        ui.print_info("Python 'rich' library is optional. High-fidelity ANSI fallback is active.")
        ui.print_info("To enable Rich UI: pip install -r requirements.txt")

    ui.print_banner("ENVIRONMENT VERIFICATION COMPLETE", "Run 'make full-pipeline' or 'make build' to start.")

if __name__ == "__main__":
    main()
