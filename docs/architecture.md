# Dvargosh Architectural Blueprint

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
