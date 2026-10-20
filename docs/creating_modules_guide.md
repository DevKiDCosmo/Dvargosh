# Comprehensive Guide: Creating Modules & Using AutoLoaders in Dvargosh

This guide provides an end-to-end walkthrough for creating, configuring, compiling, and deploying custom modules in the **Dvargosh Runtime Engine**.

---

## 1. Architectural Overview

Dvargosh decouples systems into three distinct tiers:
1. **Module (Package)**: The physical shared object (`.dylib` / `.so`). A module defines permissions, lifecycle hooks, and an optional hardware-guarded memory container.
2. **Domain (Subsystem)**: Logical partitions within a module (e.g. `telemetry`, `crypto_vault`, `worker`). Domains enforce access boundaries.
3. **Service (Function)**: Individual functional endpoints exposed by a domain. Can be called dynamically or directly via auto-generated typed proxies.

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

---

## 2. Creating a New Module

You can scaffold a new module using the interactive wizard or via non-interactive CLI flags for CI/CD.

### Method A: Interactive Wizard
```bash
make new-module
```
Or run the Python tool directly:
```bash
python3 pipeline_dvargosh/scaffold.py
```
The wizard prompts you for:
* **Module Name**: Unique lowercase identifier (e.g. `telecom`, `auth_engine`).
* **Subsystem Domain**: The primary subsystem tag (e.g. `packet`, `vault`).
* **Module Archetype**:
  * `service`: Standard non-monolithic service methods.
  * `crypto`: Cryptographic hashing and verification with hardware memory isolation.
  * `compute`: Floating-point and high-throughput computational workers.
  * `vault`: Hardware-guarded security vault.
* **Secured Memory Quota**: Quota in KB (default: 2048 KB).
* **Target Directory**: `development_modules` (recommended) or `modules`.

### Method B: Non-Interactive CLI (for CI/CD Pipelines)
```bash
python3 pipeline_dvargosh/scaffold.py \
    --name neural_net \
    --domain inference \
    --type compute \
    --description "Deep Learning Inference Subsystem" \
    --author "AI Team" \
    --secured-memory-kb 4096 \
    --non-interactive
```

---

## 3. Writing Clean C++ Services with Attribution Markers

Dvargosh allows writing pure, standard C++ functions decorated with attribution markers.

### Service Definition
In `development_modules/<name>/<name>.services.cpp`:
```cpp
#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

// Attributed with DVARGOSH_SERVICE(module:domain)
// The preprocessor expands this to an empty comment during compilation.
// The Dvargosh pipeline toolchain automatically generates the RPC bridge
// and strongly-typed C++ interface proxy.
DVARGOSH_SERVICE(telecom:packet)
std::string telecom_route(const std::string& packet_payload) {
    return "ROUTED_" + packet_payload;
}

DVARGOSH_SERVICE(telecom:packet)
double telecom_latency(double distance_km, double speed_factor) {
    return (distance_km / 300000.0) * speed_factor;
}

} // namespace dvargosh
```

### Module Lifecycle Controller
In `development_modules/<name>/<name>_module.cpp`:
```cpp
#include "dvargosh/dvargosh.hpp"

namespace dvargosh {

class TelecomModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "telecom";
            m.domain = "*"; // Scoped to telecom.*
            m.version = Version{1, 0, 0};
            m.description = "High-speed telecom packet routing";
            m.author = "Dvargosh Dev";
            m.requested_permissions = PermissionSet::all();
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        // Automatically registers functions declared in non-monolithic .cpp files
        register_auto_functions(ctx);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::TelecomModule)
```

---

## 4. Automatic Build & Proxy Generation

Whenever you add or modify a module, run:
```bash
make full-pipeline
```
This single command:
1. Scans attribution markers and generates `_generated_registration.cpp` inside `build/`.
2. Synchronizes `module.def` (sources, domains, link libraries).
3. Auto-generates `build/generated/include/dvargosh/generated/<name>_interface.hpp`.
4. Auto-generates CMake targets in `build/development_modules/DevModules.cmake`.
5. Compiles and cryptographically signs the shared library (`libmod_<name>.dylib`).
6. Runs all verification suites.

---

## 5. Using the Enhanced AutoLoader in C++

Dvargosh provides flexible loading mechanisms:

```cpp
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

auto di = std::make_shared<DIContainer>();
ModuleLoader loader(di);
loader.add_search_path("./build/modules");
loader.add_search_path("./build/development_modules");

const std::string secret_key = "dvargosh_master_signing_key_2026";
```

### 1. Universal Auto-Discovery
Introspects module headers without loading executable code:
```cpp
auto discovered = loader.discover_all_modules();
for (const auto& mod : discovered) {
    std::cout << "Discovered: " << mod.name << " (" << mod.filename << ") ABI: " << mod.abi_version << "\n";
}
```

### 2. Auto-Load All Modules (`auto_load_all`)
Automatically verifies cryptographic signatures and loads all discovered modules:
```cpp
auto res = loader.auto_load_all(secret_key);
std::cout << "Successfully loaded " << res.value() << " modules.\n";
```

### 3. Wildcard Pattern Matching (`auto_load_matching`)
Load specific categories of modules (e.g. all crypto modules):
```cpp
loader.auto_load_matching("crypto_*", secret_key);
loader.auto_load_matching("*telecom*", secret_key);
```

### 4. Domain-Driven Auto-Loading (`auto_load_domain`)
Load the module providing a specific subsystem domain on-demand:
```cpp
loader.auto_load_domain("telecom:packet", secret_key);
loader.auto_load_domain("demo_pkg:vault", secret_key);
```

### 5. Explicit Signature Loading (`load`)
```cpp
std::string sig = Crypto::sign_file(secret_key, "./build/modules/libmod_demo_pkg.dylib").value();
loader.load("demo_pkg", sig);
```

---

## 6. How to Call Exported Functions

### Option A: Auto-Generated Strongly-Typed Proxies (Recommended)
Zero `Value` boxing, zero string method names, compile-time type safety:
```cpp
#include "dvargosh/generated/telecom_interface.hpp"

using namespace dvargosh::generated::telecom;

// Direct typed call:
std::string routed = TelecomProxy::telecom_route(*di, "Payload123");
```

### Option B: Dynamic RPC with Fuzzy Suggestions
Useful for script bindings and decoupled cross-module calls:
```cpp
auto res = di->registry()->invoke("telecom_route", {Value("Payload123")});
std::string output = res.value().to_string();

// If misspelled, registry provides Levenshtein distance suggestions:
di->registry()->invoke("telecom_rout", {Value("Test")});
// Error: Method 'telecom_rout' not found. Did you mean 'telecom_route'?
```

### Option C: C++ AutoMapper Dynamic Binding
Binds any dynamic RPC method into a standard `std::function` without code generation:
```cpp
AutoMapper mapper(di);
auto my_fn = mapper.bind<std::string, const std::string&>("telecom_route");

// Call it as a regular C++ function:
std::string out = my_fn("DirectCallThroughAutoMapper");
```

---

## 7. In-Process Memory Containerization

To protect cryptographic keys, tokens, and sensitive data from buffer overruns:
```cpp
#include "dvargosh/secured_memory.hpp"

// Allocate 4 MB of hardware-guarded memory
auto space = init_own_memory_space(
    "auth_tokens",
    4 * 1024 * 1024, // 4 MB capacity
    true,            // Enable hardware PROT_NONE guard pages
    true,            // Pin pages in RAM (mlock)
    true             // Volatile zero-scrub on release
);

// Allocate within the guarded space:
void* secret_ptr = space->value()->allocate(256);
```

---

## 8. Production Build & Packaging

To compile an optimized release distribution:
```bash
make production
```
Or with custom CLI parameters:
```bash
./pipeline_dvargosh/build_production.sh --output-dir ./dist --key my_prod_key
```

### Production Package Layout (`dist/`):
* `dist/bin/`: Core runtime binaries (`dvargosh`, `dvargosh_pipeline_app`)
* `dist/modules/`: Cryptographically signed shared libraries
* `dist/include/`: C++ API headers and generated typed proxies
* `dist/docs/`: Architecture blueprint, API docs, and schema
* `dist/signatures.json`: HMAC-SHA256 signature chain manifest
"""
    with open(DOCS_DIR / "creating_modules_guide.md", "w") as f:
        f.write(content)
    print(f"[PIPELINE] Generated Module Creation Guide -> {DOCS_DIR / 'creating_modules_guide.md'}")
