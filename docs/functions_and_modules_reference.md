# Dvargosh Runtime: Master Function & Module Reference Manual

This document provides a comprehensive, end-to-end reference for developing, securing, and executing modules and functions in the **Dvargosh Runtime Engine**.

---

## Table of Contents

1. [Core Architectural Concepts](#1-core-architectural-concepts)
2. [Complete Core API & Function Reference](#2-complete-core-api--function-reference)
   - [Runtime Engine & Context](#runtime-engine--context)
   - [Domain Manager & Security Matrix](#domain-manager--security-matrix)
   - [Execution Context & Anti-Spoofing Stack](#execution-context--anti-spoofing-stack)
   - [Cryptographic Hardware-Guarded Vaults](#cryptographic-hardware-guarded-vaults)
   - [Secured Memory Spaces & Allocators](#secured-memory-spaces--allocators)
   - [Module Context (Injected Environment)](#module-context-injected-environment)
   - [AutoLoader System](#autoloader-system)
   - [AutoMapper & Direct Function Binding](#automapper--direct-function-binding)
3. [How to Create a Module (Step-by-Step)](#3-how-to-create-a-module-step-by-step)
4. [How to Create Functions (`DVARGOSH_SERVICE` & `[[]]`)](#4-how-to-create-functions-dvargosh_service--attribution)
5. [How to Secure Functions, Vaults, and Domains](#5-how-to-secure-functions-vaults-and-domains)
6. [How to Invoke & Bind Functions (3 Execution Paradigms)](#6-how-to-invoke--bind-functions-3-execution-paradigms)
   - [Paradigm 1: Dynamic RPC (`ctx->call` / `registry->invoke`)](#paradigm-1-dynamic-rpc-ctx-call--registry-invoke)
   - [Paradigm 2: Auto-Generated Strongly-Typed Proxies (`_interface.hpp`)](#paradigm-2-auto-generated-strongly-typed-proxies-_interfacehpp)
   - [Paradigm 3: Direct Function Binding with AutoMapper (`_bind.hpp`)](#paradigm-3-direct-function-binding-with-automapper-_bindhpp)
7. [Diagnostics: Root Cause Analysis of CTest Hanging Issue](#7-diagnostics-root-cause-analysis-of-ctest-hanging-issue)

---

## 1. Core Architectural Concepts

Dvargosh decouples software into three isolation tiers:

```
+-----------------------------------------------------------------------------------+
|                                  DVARGOSH RUNTIME                                 |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                            MODULE (Shared Object)                           |  |
|  |  [Physical Container • Hardware-Guarded Secured Space • Cryptographic HMAC] |  |
|  |                                                                             |  |
|  |  +--------------------------------+     +--------------------------------+  |  |
|  |  |    DOMAIN: <name>:vault        |     |    DOMAIN: <name>:worker       |  |  |
|  |  |  [Hardware-Guarded Vault]      |     |  [Computational Sandbox]       |  |  |
|  |  |  * write_secret()              |     |  * worker_power()              |  |  |
|  |  |  * read_secret()               |     |  * execute_task()              |  |  |
|  |  +--------------------------------+     +--------------------------------+  |  |
|  |                   ▲                                      ▲                  |  |
|  |                   └────────────── SCOPED '*' ────────────┘                  |  |
|  |                              (Package Orchestrator)                         |  |
|  +-----------------------------------------------------------------------------+  |
|                                          ▲                                        |
|                                          │ Cross-Domain Access Matrix             |
|                                          ▼ (Blacklist > Whitelist > Rejection)    |
|  +-----------------------------------------------------------------------------+  |
|  |                     CALLER DOMAIN: captives:intruder                        |  |
|  |  * get_domain_vault("captives:vault") => REJECTED (Permission Denied)       |  |
|  |  * call("hello_world.get_safe_vault_key") => REJECTED (Cross-Domain Block)  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

1. **Module**: The physical shared library (`.dylib` / `.so`). Governed by a `module.def` manifest, lifecycle hooks, and an optional RAM-locked secured memory pool.
2. **Domain**: Logical isolation boundaries. Every function and vault belongs to an explicit domain (e.g. `captives:vault`, `telemetry`, `compute`).
3. **Service / Function**: Named functional endpoints. Services are registered under canonical aliases of the form `module.function`.

---

## 2. Complete Core API & Function Reference

### Runtime Engine & Context

Located in `#include "dvargosh/runtime.hpp"`:

- `Runtime::get_context(const std::string& module_name) -> ModuleContext*`  
  Retrieves the active injected `ModuleContext` pointer for a loaded module. Returns `nullptr` if the module is not loaded or not initialized.
- `Runtime::register_module_context(const std::string& module_name, ModuleContext* ctx)`  
  Registers a module context into the global runtime context lookup table (called internally during module loading).
- `Runtime::unregister_module_context(const std::string& module_name)`  
  Removes a module context from the runtime table on unload.

---

### Domain Manager & Security Matrix

Located in `#include "dvargosh/domain.hpp"`:

- `dm->create_domain(name, policy, secured_memory_bytes, use_guard_pages) -> Result<Domain*>`  
  Allocates a logical domain with custom permissions and optional page-guarded memory.
- `dm->get_domain(name) -> Domain*`  
  Fetches pointer to a domain configuration.
- `dm->allow_cross_domain(from_domain, to_domain) -> Result<void>`  
  Grants `from_domain` permission to call services or access resources in `to_domain`.
- `dm->blacklist_domain(from_domain, to_domain) -> Result<void>`  
  Explicitly adds `to_domain` to the denylist of `from_domain`. **Blacklist rules strictly take precedence over whitelists or wildcards.**
- `dm->unblacklist_domain(from_domain, to_domain) -> Result<void>`  
  Removes a domain from the blacklist.
- `dm->is_cross_domain_blacklisted(from_domain, to_domain) -> bool`  
  Checks if access from `from_domain` to `to_domain` is forbidden by a blacklist rule.
- `dm->check_cross_domain_access(from_domain, to_domain) -> bool`  
  Evaluates both blacklist and whitelist rules. Returns `true` if authorized, `false` otherwise.
- `dm->get_domain_vault(domain_name, vault_name) -> Result<std::shared_ptr<Vault>>`  
  **Secure Vault Accessor.** Automatically resolves the calling domain via `ExecutionContext::current_domain()`, verifies that caller is not blacklisted, and checks cross-domain access before returning the vault handle.
- `dm->get_domain_space(domain_name, caller_domain) -> Result<SecuredMemorySpace*>`  
  Retrieves the raw secured memory space pointer after validating cross-domain permissions.
- `dm->unload_domain_space(domain_name) -> Result<void>`  
  Scrubs and deallocates (`munmap`) the hardware-guarded space of a domain.
- `dm->unload_domain_vaults(domain_name) -> Result<void>`  
  Wipes all secret slots, removes memory protections, and destroys vaults in a domain.
- `dm->unplug_domain(domain_name, loader) -> Result<size_t>`  
  Hot-unplugs all modules and securely tears down all memory spaces belonging to that domain.

---

### Execution Context, Anti-Spoofing & Command Memory Stack

Located in `#include "dvargosh/execution_context.hpp"` and `#include "dvargosh/command_memory.hpp"`:

- `ExecutionContext::current_domain() -> std::string`  
  Returns the active domain of the currently executing stack frame. If no frame is active, returns `"system"`. If tampering is detected, returns `"__COMPROMISED__"`.
- `ExecutionContext::current_module() -> std::string`  
  Returns the active module name of the currently executing frame.
- `ExecutionContext::caller_domain() -> std::string`  
  Returns the immediate upstream caller domain.
- `ExecutionContext::caller_module() -> std::string`  
  Returns the immediate upstream caller module.
- `ExecutionContext::is_system() -> bool`  
  Returns `true` if running in unrestricted administrative system context.
- `ExecutionContext::allocate_command_memory(size, alignment) -> void*`  
  Allocates scratchpad memory within the active command's execution frame. All memory is automatically volatile-scrubbed and unmapped upon command completion.
- `ExecutionContext::current_command_memory() -> CommandMemory*`  
  Retrieves a pointer to the active command's memory container.
- `ExecutionContext::command_memory_used() -> size_t`  
  Returns the number of scratchpad bytes allocated by the current command.
- `ExecutionContext::command_memory_capacity() -> size_t`  
  Returns the capacity limit of the current command's memory page.
- `ExecutionContext::validate_stack_integrity() -> Result<void>`  
  Verifies the cryptographic HMAC-SHA256 signature of every call frame on the thread-local call stack. Detects internal memory mutations and pointer tampering.
- `ExecutionContext::frame_depth() -> size_t`  
  Returns the depth of the active call stack on the current thread.

---

### Cryptographic Hardware-Guarded Vaults & Binary Memory

Located in `#include "dvargosh/vault.hpp"`:

- `vault->write_secret(key, value) -> Result<void>`  
  Temporarily unprotects the memory page (`PROT_READ | PROT_WRITE`), writes the secret, recalculates cryptographic hash, and automatically seals the page (`PROT_READ`). Non-owner domains are rejected immediately.
- `vault->write_memory(key, data_ptr, size) -> Result<void>`  
  Writes an arbitrary binary memory buffer into the hardware-guarded vault memory pool.
- `vault->read_secret(key) -> Result<std::string>`  
  Validates caller ownership or cross-domain permissions, verifies checksum integrity, and returns the secret string.
- `vault->read_memory(key) -> Result<std::vector<uint8_t>>`  
  Validates caller domain permissions, verifies checksum integrity, and returns the raw binary memory buffer.
- `vault->wipe_secret(key) -> Result<void>`  
  Securely volatile-zeros the memory slot of a specific key inside the vault without affecting other slots.
- `vault->memory_stats() -> VaultMemoryStats`  
  Returns detailed memory telemetry (capacity, used bytes, remaining bytes, slot count, sealing status, and guard pages).
- `vault->list_slots() -> std::vector<VaultSlotInfo>`  
  Returns the table of stored memory slots (key, offset, size, checksum, and wiped status).
- `vault->seal() -> Result<void>`  
  Applies hardware-level read-only protection (`PROT_READ`) via `mprotect`.
- `vault->unseal() -> Result<void>`  
  Restores write access (`PROT_READ | PROT_WRITE`) if the caller is authorized.
- `vault->unload()`  
  Wipes all secret entries, zeros the memory pool, and deallocates the underlying hardware space.
- `vault->read_secret(key) -> Result<std::string>`  
  Validates caller ownership or cross-domain permissions, verifies checksum integrity, and returns the secret.
- `vault->seal() -> Result<void>`  
  Applies hardware-level read-only protection (`PROT_READ`) via `mprotect`.
- `vault->unseal() -> Result<void>`  
  Restores write access (`PROT_READ | PROT_WRITE`) if the caller is authorized.
- `vault->unload()`  
  Wipes all secret entries, zeros the memory pool, and deallocates the underlying hardware space.

---

### Secured Memory Spaces & Allocators

Located in `#include "dvargosh/secured_memory.hpp"` and `#include "dvargosh/allocator.hpp"`:

- `SecuredMemorySpace::create(config, policy) -> Result<std::unique_ptr<SecuredMemorySpace>>`  
  Creates an anonymous `mmap` region with front and rear `PROT_NONE` guard pages, RAM-locking (`mlock`), and quota verification.
- `space->allocate(size, alignment) -> void*`  
  Carves out a sub-allocation within the secured container.
- `space->reset()`  
  Volatile-zeros the used portion of the space and rewinds the allocation offset to 0.
- `space->scrub()`  
  Volatile-zeros the entire capacity of the container.
- `space->unload()`  
  Restores write protection, volatile-zeros memory, calls `munlock`, and executes `munmap` to safely return pages to the operating system.
- `TrackedAllocator`  
  Provides heap allocation tracking with strict quota enforcement. If allocations exceed the module quota defined in `module.def`, further allocations are blocked (`QuotaExceeded`).

---

### Module Context (Injected Environment)

Located in `#include "dvargosh/di_container.hpp"`:

- `ctx.call(method_name, args) -> Result<Value>`  
  Invokes a remote or local service by canonical alias (`module.function`). Automatically resolves caller identity and enforces cross-domain permissions.
- `ctx.inject<Interface>(service_name) -> Result<std::shared_ptr<Interface>>`  
  Injects a strongly-typed C++ interface implementation registered in the DI container.
- `ctx.register_service<Interface>(name, impl) -> Result<void>`  
  Registers a C++ service implementation under the module's domain.
- `ctx.register_method(name, desc, fn) -> Result<void>`  
  Registers a raw dynamic lambda/function pointer.
- `ctx.emit(topic, payload) -> Result<void>`  
  Publishes an asynchronous event to the event bus.
- `ctx.on(topic, handler) -> Result<uint64_t>`  
  Subscribes to an event bus topic.
- `ctx.domain_space() -> SecuredMemorySpace*`  
  Accesses the module's assigned domain memory space.
- `ctx.allocator() -> TrackedAllocator*`  
  Accesses the quota-tracked heap allocator.
- `ctx.arena() -> ArenaAllocator*`  
  Accesses the fast bump-pointer arena for temporary per-task allocations.

---

### AutoLoader System

Located in `#include "dvargosh/module_loader.hpp"`:

- `loader.load("name", "signature") -> Result<void>`  
  Loads a module shared library by name after verifying its HMAC-SHA256 signature against `signatures.json`.
- `loader.auto_load_matching("pattern*") -> size_t`  
  Discovers and loads all modules whose name matches a wildcard pattern (e.g. `demo_*`, `telecom_*`).
- `loader.auto_load_domain("subsystem:tag") -> Result<void>`  
  Scans all module `.def` files and automatically loads the provider module that hosts the requested domain.
- `loader.discover_all_modules() -> std::vector<DiscoveredModuleInfo>`  
  Probes all `.dylib` / `.so` libraries in the module directory, extracts metadata symbols (`g_dvargosh_module_name`, `g_dvargosh_abi_version`, `g_dvargosh_build_id`), and returns catalog information.

---

### AutoMapper & Direct Function Binding

Located in `#include "dvargosh/automapper.hpp"`:

- `AutoMapper mapper(di)`  
  Constructs an AutoMapper instance attached to the DI container.
- `mapper.has_service("module.function") -> bool`  
  Returns true if the canonical service is registered in the runtime.
- `mapper.find_domain_for_service("module.function") -> std::string`  
  Performs dynamic reflection to retrieve the domain that owns the method.
- `mapper.bind<Ret(Args...)>("module.function") -> std::function<Ret(Args...)>`  
  **Ties a dynamic RPC method directly to a native C++ callable `std::function`.** No manual unpacking of `Value` or handling of `invoke()` status codes is required.

---

## 3. How to Create a Module (Step-by-Step)

Creating a module in Dvargosh requires 3 straightforward files inside `development_modules/<module_name>/`.

### Step 1: Create the Module Directory

```bash
mkdir -p development_modules/auth_system
```

### Step 2: Define `module.def` Manifest

In `development_modules/auth_system/module.def`:

```ini
[module]
name = auth_system
version = 1.0.0
description = High-Security Authentication & Token Subsystem
author = Security Team
secured_memory_kb = 1024
domains = auth:token, auth:vault, *
sources = auth_module.cpp, auth_services.cpp
link_libraries = dvargosh_core
auto_load = true
```

### Step 3: Implement Module Lifecycle (`auth_module.cpp`)

In `development_modules/auth_system/auth_module.cpp`:

```cpp
#include "dvargosh/dvargosh.hpp"

namespace dvargosh {

class AuthSystemModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "auth_system";
            m.domain = "*";
            m.version = Version{1, 0, 0};
            m.description = "Authentication & Token Subsystem";
            m.author = "Security Team";
            m.requested_permissions = PermissionSet::all();
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        DomainManager* dm = ctx.domain_manager();
        if (dm) {
            // Create domains with appropriate security policies
            dm->create_domain("auth:vault", SecurityPolicy::strict(), 64 * 1024, true);
            dm->create_domain("auth:token", SecurityPolicy::standard());

            // Create hardware-guarded vault
            VaultConfig vcfg;
            vcfg.name = "jwt_signing_keys";
            vcfg.owner_domain = "auth:vault";
            vcfg.owner_module = "auth_system";
            vcfg.capacity_bytes = 16 * 1024;
            vcfg.security_level = VaultSecurityLevel::TamperProof;
            vcfg.use_guard_pages = true;
            vcfg.auto_seal_on_write = true;

            auto v_res = dm->create_vault(vcfg);
            if (v_res.is_ok()) {
                v_res.value()->write_secret("SIGNING_SECRET", "TOP_SECRET_JWT_SIGNING_KEY_2026");
            }
        }

        // Automatically registers all services declared across all non-monolithic files!
        register_auto_functions(ctx);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

} // namespace dvargosh

// Export dynamic module entry symbol
DVARGOSH_EXPORT_MODULE(dvargosh::AuthSystemModule)
```

### Step 4: Run the Build Pipeline

```bash
./pipeline_dvargosh/build_pipeline.sh
```

The toolchain automatically:

1. Detects `auth_system` in `development_modules/`.
2. Generates CMake build rules in `DevModules.cmake`.
3. Auto-generates C++ registration adapters (`_generated_registration.cpp`).
4. Generates strongly-typed C++ interfaces (`auth_system_interface.hpp`), API constants (`auth_system_api.hpp`), and AutoMapper binders (`auth_system_bind.hpp`).
5. Signs the resulting library using HMAC-SHA256.

---

## 4. How to Create Functions (`DVARGOSH_SERVICE` & Attribution)

Dvargosh supports non-monolithic file layouts. You can place your service functions in any `.cpp` file inside your module directory.

### Syntax 1: `DVARGOSH_SERVICE(module:domain)` Macro

In `development_modules/auth_system/auth_services.cpp`:

```cpp
#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

// Normal Service Function in "auth:token" domain
DVARGOSH_SERVICE(auth:token)
std::string generate_token(const std::string& username) {
    return "TOKEN_" + username + "_SECURE_SESSION";
}

// Mathematical / Computational Service Function
DVARGOSH_SERVICE(auth:token)
double compute_risk_score(double failed_attempts, double geo_distance) {
    return (failed_attempts * 15.0) + (geo_distance / 100.0);
}

} // namespace dvargosh
```

### Syntax 2: Attribute-Based Declaration

```cpp
[[dvargosh::export("auth:token")]]
std::string validate_token(const std::string& token) {
    return token.find("TOKEN_") == 0 ? "VALID" : "INVALID";
}
```

### Naming & Alias Overrides

The pipeline automatically generates canonical aliases in the format:

```
module.function
```

- **Example:** `auth_system.generate_token`
- The old raw un-prefixed name (`generate_token`) is ditched to avoid namespace collisions.
- The domain is kept as a strict security barrier, but omitted from the invocation alias for clean ergonomics.

---

## 5. How to Secure Functions, Vaults, and Domains

Here is the complete implementation pattern for securing functions, resolving caller domains, and enforcing blacklist/whitelist rules:

```cpp
#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

DVARGOSH_SERVICE(captives:vault)
std::string get_safe_vault_key() {
    // 1. Fetch active module context
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->domain_manager()) return "ERROR_NO_CONTEXT";

    // 2. Check if caller domain is blacklisted or unauthorized
    // ExecutionContext::current_domain() resolves caller frame automatically and securely
    std::string caller = ExecutionContext::current_domain();
    if (ctx->domain_manager()->is_cross_domain_blacklisted(caller, "captives:vault")) {
        return "ACCESS_DENIED: Calling domain '" + caller + "' is explicitly blacklisted";
    }

    // 3. Authorized access: get_domain_vault() performs kernel-level blacklist/whitelist verification
    auto vault_res = ctx->domain_manager()->get_domain_vault("captives:vault", "captives_vault");
    if (!vault_res.is_ok()) {
        return "ACCESS_DENIED: " + vault_res.error_message();
    }

    // 4. Read secret key from hardware-guarded vault
    auto secret_res = vault_res.value()->read_secret("ROOT_KEY");
    if (!secret_res.is_ok()) {
        return "READ_FAILED: " + secret_res.error_message();
    }

    return secret_res.value();
}

} // namespace dvargosh
```

### Security Guarantees:

1. **Automatic Frame Resolution**: Inside `get_safe_vault_key()`, `ExecutionContext::current_domain()` returns `"captives:vault"`.
2. **Anti-Tampering HMAC Check**: If any malicious code attempts to mutate `CallFrame::domain_name` in memory, `validate_stack_integrity()` fails with `StatusCode::SecurityTampering` and aborts execution.
3. **Blacklist Precedence**: Even if a domain is authorized via a wildcard `*`, calling `dm->blacklist_domain("intruder", "captives:vault")` strictly denies all access attempts.

---

## 6. How to Invoke & Bind Functions (3 Execution Paradigms)

Dvargosh provides three distinct paradigms to call functions depending on your architecture:

### Paradigm 1: Dynamic RPC (`ctx->call` / `registry->invoke`)

Best for dynamic plugin architectures, scripting, and loosely-coupled messaging:

```cpp
// Within a module using its injected ModuleContext:
auto res = ctx->call("demo_pkg.demo_pkg_vault_hash", {Value("DvargoshData")});
if (res.is_ok()) {
    std::string hash = res.value().to_string();
} else {
    std::cerr << "Invocation failed: " << res.error_message() << "\n";
}

// In the host application via DIContainer:
auto res = di->registry()->invoke("demo_pkg.demo_pkg_worker_power", {Value(2.0), Value(8.0)});
double result = res.value().as_double(); // 256.0
```

- **Fuzzy Suggestions:** If you make a typo like `"demo_pkg.demo_pkg_worker_pow"`, the engine returns:
  `Method 'demo_pkg.demo_pkg_worker_pow' not found in registry. Did you mean 'demo_pkg.demo_pkg_worker_power'?`

---

### Paradigm 2: Auto-Generated Strongly-Typed Proxies (`_interface.hpp`)

Best for clean C++ code without manual `Value` packing or string typing.

The pipeline automatically generates typed proxy classes in `build/generated/include/<module>_interface.hpp`:

```cpp
#include "dvargosh/generated/demo_pkg_interface.hpp"
#include "dvargosh/generated/helloWorld_interface.hpp"

using namespace dvargosh::generated::demo_pkg;
using namespace dvargosh::generated::helloWorld;

// Direct strongly-typed static calls:
std::string hash = DemoPkgProxy::demo_pkg_vault_hash(*di, "Payload");
double power     = DemoPkgProxy::demo_pkg_worker_power(*di, 3.0, 4.0); // Returns 81.0
std::string key  = HelloWorldProxy::get_safe_vault_key(*di);
```

- **Compiler Type Safety**: Arguments and return types are checked at compile time.
- **Zero Boilerplate**: Automatically unwraps `Result<Value>` and throws `DvargoshException` on error.

---

### Paradigm 3: Direct Function Binding with AutoMapper (`_bind.hpp`)

Best when you want to **tie dynamic RPC methods directly to native C++ callables (`std::function`)** so they behave like normal C++ functions.

#### Option A: Using Pipeline-Generated Binders (`<module>_bind.hpp`)

```cpp
#include "dvargosh/generated/demo_pkg_bind.hpp"
#include "dvargosh/generated/crypto_accelerator_bind.hpp"

// Instantiate typed binder attached to DI container
dvargosh::generated::demo_pkg::DemoPkgBinder demo_binder(di);
dvargosh::generated::crypto_accelerator::CryptoAcceleratorBinder crypto_binder(di);

// Call bound functions directly without invoke():
std::string hash = demo_binder.demo_pkg_vault_hash("SecretToken");
double val       = demo_binder.demo_pkg_worker_power(2.0, 5.0); // 32.0
std::string sha  = crypto_binder.accelerator_sha256("Payload");
```

#### Option B: Dynamic Reflection Binding via `AutoMapper`

```cpp
#include "dvargosh/automapper.hpp"

AutoMapper mapper(di);

// Bind dynamic method 'demo_pkg.demo_pkg_worker_power' to a native std::function:
auto power_fn = mapper.bind<double(double, double)>("demo_pkg.demo_pkg_worker_power");

// Call directly:
double result = power_fn(2.0, 10.0); // 1024.0

// Bind string hashing method:
auto hash_fn = mapper.bind<std::string(std::string)>("demo_pkg.demo_pkg_vault_hash");
std::string digest = hash_fn("DvargoshData");
```

---

## 7. Diagnostics: Root Cause Analysis of CTest Hanging Issue

### The Problem

During automated test runs (`ctest` and `./pipeline_dvargosh/build_pipeline.sh`), the test execution froze indefinitely on:

```
Start 1: UnitTests
  [RUN] test_secured_memory_init...
```

### The Root Cause: Recursive Mutex Deadlock

In `src/core/secured_memory.cpp`:

```cpp
void SecuredMemorySpace::unload() {
    std::lock_guard<std::mutex> lock(m_mutex); // Lock #1
    if (m_total_mapped) {
        ...
        if (m_config.scrub_on_destroy) {
            scrub(); // Calls scrub() which attempts Lock #2!
        }
        munmap(m_total_mapped, m_total_mapped_size);
    }
}

void SecuredMemorySpace::scrub() {
    std::lock_guard<std::mutex> lock(m_mutex); // DEADLOCK! m_mutex is non-recursive
    if (m_usable_memory && m_usable_size > 0) {
        secure_zero(m_usable_memory, m_usable_size);
    }
}
```

When `test_secured_memory_init` finished, the `std::unique_ptr<SecuredMemorySpace>` object was destroyed:

1. `~SecuredMemorySpace()` called `unload()`.
2. `unload()` acquired `m_mutex`.
3. `unload()` called `scrub()`.
4. `scrub()` attempted to acquire `m_mutex` on the same thread.
5. Standard `std::mutex` is non-recursive; the thread immediately deadlocked waiting on itself, causing `UnitTests` and `ctest` to hang indefinitely.

### The Fix

In `SecuredMemorySpace::unload()`, replace the nested call to `scrub()` with the direct internal `secure_zero()` function:

```cpp
void SecuredMemorySpace::unload() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_total_mapped) {
        if (m_usable_memory && m_usable_size > 0) {
            mprotect(m_usable_memory, m_usable_size, PROT_READ | PROT_WRITE);
            if (m_config.scrub_on_destroy) {
                secure_zero(m_usable_memory, m_usable_size); // Thread-safe zeroing without deadlock
            }
            if (m_config.lock_in_ram) {
                munlock(m_usable_memory, m_usable_size);
            }
        }
        munmap(m_total_mapped, m_total_mapped_size);
        m_total_mapped = nullptr;
        m_usable_memory = nullptr;
        m_total_mapped_size = 0;
        m_usable_size = 0;
        m_used_offset = 0;
    }
}
```

With this change, all 30/30 unit tests, app loader integration tests, pipeline apps, and Docker containers execute in milliseconds with 100% pass rate.

---

## 8. Interactive CLI: Memory & Vault Commands

The interactive console provides comprehensive commands to monitor, audit, and manipulate domain secured memory spaces and cryptographic vaults live.

### Memory Commands

- `memory status` (or `memory`):  
  Prints a system-wide memory report showing all domains, memory capacities, used bytes, and active vaults.
- `memory domain <domain_name>`:  
  Displays detailed memory allocation stats (capacity, used bytes, remaining bytes, raw base pointer) for a specific domain.
- `memory scrub <domain_name>`:  
  Executes a hardware volatile zeroing scrub across the entire secured space of the domain.
- `memory reset <domain_name>`:  
  Resets the allocation offset to 0 and scrubs active memory in the domain.

### Vault Commands

- `vaults`:  
  Lists all active vaults across all domains, their owner module/domain, capacity, used memory, slot count, and hardware-sealing status.
- `vault info <domain> <vault_name>`:  
  Displays full technical telemetry for the vault, including security level, guard pages, remaining capacity, and individual stored memory slots with offsets and SHA-256 checksums.
- `vault read <domain> <vault_name> <key>`:  
  Reads a secret value after verifying caller permissions and cryptographic integrity.
- `vault write <domain> <vault_name> <key> <value>`:  
  Writes a secret into the vault with automatic hardware page sealing.
- `vault wipe <domain> <vault_name> <key>`:  
  Volatile-zeros the memory slot occupied by `<key>`, removing it securely without affecting other stored secrets.
- `vault seal <domain> <vault_name>`:  
  Applies hardware-level write protection (`mprotect(PROT_READ)`) to the vault memory pages.
- `vault unseal <domain> <vault_name>`:  
  Temporarily restores write access for authorized owner modifications.
- `vault verify <domain> <vault_name>`:  
  Runs a cryptographic checksum verification pass across all stored slots to detect any in-memory bit rot or tampering.
