# Dvargosh Invocation & Cross-Domain Security Guide

This guide explains how to properly invoke functions and services in the **Dvargosh Runtime Engine**, explains common misconceptions when calling cross-module services from inside plugins, and details how domain isolation protects hardware-guarded safe spaces.

---

## 1. Why `auto di = std::make_shared<DIContainer>()` Fails Inside a Module

Consider this common mistake when attempting to invoke another service from inside a module function:

```cpp
// ❌ INCORRECT: Creating a new DIContainer inside a service method
DVARGOSH_SERVICE(captives:hello_world)
std::string invokeothers() {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    auto hash_res = di->registry()->invoke("demo_pkg_vault_hash", {Value("DvargoshData")});
    return hash_res.is_ok() ? hash_res.value().to_string() : "Error";
}
```

### Root Cause Analysis

1. **Detached In-Memory World**:
   `DIContainer` is **not** a stateless handle or thread-local locator; it is the **central Dependency Injection Host** that owns the running system's active `Registry`, `DomainManager`, and `ResourceManager`. When the application boots, the host creates **one** container where all modules and domains are loaded.
   Calling `std::make_shared<DIContainer>()` allocates a **brand new, empty container** on the heap.
   - Its `Registry` contains `0` services and `0` methods.
   - Its `DomainManager` contains only default domains, with none of your active module domains.

2. **Unconfigured and Idle Loader**:
   `ModuleLoader loader(di);` binds the loader to the new, empty container. However:
   - No search paths have been configured.
   - `loader.load(...)` was never invoked.
   The target service `demo_pkg_vault_hash` was loaded into the **host's** container, not this temporary local instance.

3. **Guaranteed Failure**:
   When `di->registry()->invoke("demo_pkg_vault_hash", ...)` is called on the new container, it searches its empty registry, finds nothing, and fails with `StatusCode::SymbolNotFound`:
   ```
   [ERROR] Method 'demo_pkg_vault_hash' not found in registry.
   ```

---

## 2. How to Call Functions Correctly in Dvargosh

Dvargosh provides **three official patterns** for calling functions depending on whether you need dynamic cross-module RPC, compile-time typed proxies, or auto-bound callbacks.

### Pattern 1: Dynamic Invocation via `Runtime::get_context` or `ModuleContext`

When inside a module function, retrieve the module's active context via `dvargosh::Runtime`:

```cpp
// ✅ CORRECT: Using the module's active host context
DVARGOSH_SERVICE(captives:hello_world)
std::string invokeothers() {
    auto* ctx = dvargosh::Runtime::get_context("hello_world");
    if (!ctx) return "Error: No active module context";

    // 1. High-level call (automatically tags caller_module and caller_domain):
    auto hash_res = ctx->call("demo_pkg_vault_hash", {dvargosh::Value("DvargoshData")});

    // 2. Or direct registry invocation:
    // auto hash_res = ctx->registry()->invoke("demo_pkg_vault_hash", {Value("DvargoshData")}, "hello_world", "captives:hello_world");

    return hash_res.is_ok() ? hash_res.value().to_string() : "Error: " + hash_res.error_message();
}
```

#### Why This Works:
* `Runtime::get_context("hello_world")` retrieves the real `ModuleContext` injected into the module during `on_load()`.
* `ctx->call(...)` automatically passes your module's identity and domain to enforce security boundaries.
* The call routes through the central host `Registry` where all active modules reside.

---

### Pattern 2: Strongly-Typed Interface Proxies (Zero `invoke()` Overhead)

When calling from an application or module that includes the pipeline-generated interface header (`<module>_interface.hpp`):

```cpp
// Include the pipeline-generated header
#include "dvargosh/generated/demo_pkg_interface.hpp"

using namespace dvargosh::generated::demo_pkg;

void run_typed_example(dvargosh::DIContainer& di) {
    // Direct, compile-time typed machine call:
    // No Value packing, no string method name lookup, full compiler type-checking!
    std::string secret_hash = DemoPkgProxy::demo_pkg_vault_hash(di, "MySecureData");
    double result = DemoPkgProxy::demo_pkg_worker_power(di, 2.0, 8.0);
}
```

---

### Pattern 3: AutoMapper Typed Binders (`<module>_bind.hpp`)

When you want standard `std::function` callables without manually unboxing `Value` variants:

```cpp
#include "dvargosh/generated/demo_pkg_bind.hpp"

using namespace dvargosh::generated::demo_pkg;

void run_binder_example(std::shared_ptr<dvargosh::DIContainer> di) {
    // Automatically binds all RPC methods into typed std::function members
    auto binder = Binder::bind(di);

    // Call as standard C++ function:
    std::string hash = binder.demo_pkg_vault_hash("MySecretPayload");
    double val = binder.demo_pkg_worker_power(3.0, 4.0);
}
```

---

## 3. Safe Spaces & Cross-Domain Security Isolation

Dvargosh implements a **3-tier hierarchy**:
* **Module (Package)**: The physical shared library (`.dylib` / `.so`).
* **Domain (Subsystem)**: A logical security boundary with its own security policy and hardware-guarded memory container.
* **Service (Function)**: Individual functional capabilities exposed by a domain.

```
+--------------------------------------------------------------------------+
|                        MODULE: hello_world                               |
|                                                                          |
|  +--------------------------------+    +------------------------------+  |
|  |     DOMAIN: captives:vault     |    |   DOMAIN: captives:intruder  |  |
|  |  [64 KB Hardware Guard Space]  |    |     [Strict Security Policy] |  |
|  |   Key: "SECURE_KEY_NAM_..."    |    |                              |  |
|  |  +--------------------------+  |    |  +------------------------+  |  |
|  |  | get_safe_vault_key()     |  |    |  | intruder_steal_key()   |  |  |
|  |  +--------------------------+  |    |  +------------------------+  |  |
|  +--------------------------------+    +------------------------------+  |
|                  ▲                                     │                 |
|                  │           DENIED (SIGSEGV/403)      │                 |
|                  └─────────────────────────────────────┘                 |
+--------------------------------------------------------------------------+
```

### Complete Example in `helloWorld` Module

#### Step 1: Initializing Safe Space & Intruder Domains (`helloworld_module.cpp`)
```cpp
Result<void> HelloWorldModule::on_load(ModuleContext& ctx) {
    DomainManager* dm = ctx.domain_manager();
    if (dm) {
        // 1. Create safe domain "captives:vault" with 64 KB hardware-guarded memory space (mmap + PROT_NONE guard pages)
        dm->create_domain("captives:vault", SecurityPolicy::strict(), 64 * 1024, true);

        // Store the master secret key directly in the hardware-guarded space
        auto* space = dm->get_domain_space("captives:vault");
        if (space) {
            char* key_buf = static_cast<char*>(space->allocate(64));
            std::strcpy(key_buf, "SECURE_KEY_NAM_CAPTIVES_9988_XYZ");
        }

        // 2. Create isolated intruder domain "captives:intruder"
        dm->create_domain("captives:intruder", SecurityPolicy::strict());
        // NOTE: captives:intruder is DELIBERATELY NOT GRANTED access to captives:vault!
    }

    register_auto_functions(ctx);
    return Result<void>::success();
}
```

#### Step 2: Defining the Access Functions (`helloworld.services.cpp`)
```cpp
// 1. Authorized Access: Calling from within "captives:vault"
DVARGOSH_SERVICE(captives:vault)
std::string get_safe_vault_key() {
    auto* ctx = Runtime::get_context("hello_world");
    auto space_res = ctx->domain_manager()->get_domain_space("captives:vault", "captives:vault");
    if (!space_res.is_ok()) return "ACCESS_DENIED";

    char* key_ptr = static_cast<char*>(space_res.value()->raw_base());
    return key_ptr ? std::string(key_ptr) : "EMPTY_KEY";
}

// 2. Unauthorized Access: Calling from outside domain ("captives:intruder")
DVARGOSH_SERVICE(captives:intruder)
std::string intruder_access_safe_space() {
    auto* ctx = Runtime::get_context("hello_world");
    // Cross-Domain Violation: "captives:intruder" requests the memory container of "captives:vault"
    auto space_res = ctx->domain_manager()->get_domain_space("captives:vault", "captives:intruder");
    if (!space_res.is_ok()) {
        // REJECTED with StatusCode::PermissionDenied!
        return "REJECTED: " + space_res.error_message();
    }
    return "UNEXPECTED_SUCCESS";
}
```

### Verification Matrix

| Caller Domain | Target Domain | Operation | Result |
| :--- | :--- | :--- | :--- |
| `captives:vault` | `captives:vault` | Memory space read (`get_safe_vault_key`) | **Granted (200 OK)** -> Returns Key |
| `captives:intruder` | `captives:vault` | Direct memory space request | **Rejected (403 PermissionDenied)** |
| `captives:intruder` | `captives:vault` | RPC service call (`intruder_invoke_vault`) | **Rejected (403 PermissionDenied)** |
| `system` | `*` | Any operation | **Granted (Universal Host Privilege)** |
| `authorized_caller` | `captives:vault` | `dm->allow_cross_domain("caller", "captives:vault")` | **Granted after explicit grant** |
