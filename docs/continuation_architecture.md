# Dvargosh Continuation Architecture

**Status:** Proposal — supersedes nothing; complements `docs/architecture.md` (as-built blueprint).
**Date:** 2026-10-26
**Scope:** (1) Security audit findings of the current codebase and their remediation plan, (2) the structural architecture for the next build-out phases: **telemetry/monitoring stacks (memory, IO, network, CPU)**, the **IO stack**, the **networking stack**, and the longer-term execution-hardening track (JIT trampolines).

---

## 1. Where the system stands (as-built summary)

Dvargosh is an in-process, plugin-style C++17 runtime. The load-bearing components:

| Layer | Components | Role |
|---|---|---|
| ABI boundary | `module_header.hpp` (packed `ModuleHeaderRaw`), `dvargosh_module_create/destroy` exports, `dvargosh_abi_version` | Zero-execution binary inspection before any module code runs |
| Loading | `module_loader.cpp`, `module_catalog.cpp` | Discovery, HMAC-SHA256 signature gate, header↔manifest identity cross-check, lifecycle (`on_load` → `on_start` → `on_stop` → `on_unload`), `dlopen(RTLD_NOW\|RTLD_LOCAL)` |
| Isolation | `domain.cpp`, `permissions.cpp`, `execution_context.cpp` | Domain allow/blacklists, permission bitmask intersection (host ceiling ∩ manifest request), thread-local call-frame stack with HMAC anti-tamper tokens |
| Memory | `secured_memory.cpp`, `command_memory.cpp`, `allocator.cpp`, `vault.cpp` | `mmap` + `PROT_NONE` guard pages, `mlock`, volatile scrubbing, bump allocators with overflow-checked arithmetic, `TrackedAllocator` quotas, sealed vaults with SHA-256 slot checksums and `mprotect` sealing |
| Services | `registry.cpp`, `di_container.cpp`, `event_bus.cpp`, `resource_manager.cpp`, `runtime.cpp` | Dynamic RPC with alias resolution + Levenshtein suggestions, per-method policy capture at registration, synchronous event bus, ref-counted resource table, service-locator |
| Pipeline | `pipeline_dvargosh/*.py`, `tools/dvargosh_tool.py` | Marker scanning → `_generated_registration.cpp`, typed proxies/binders, embedded `ModuleHeaderRaw` in `.rodata`, `module.def` sync, CMake generation, HMAC signing |
| Telemetry (seed) | `modules/monitor` | Metric map, memory-occupation report over `TrackedAllocator` + `DomainManager`, event-driven counters, dashboard RPC |

The honest statement of the **security model**: every module runs *in the host process address space*. All isolation today (permissions, domains, vault sealing, call-frame tokens) is **cooperative/advisory** — it protects against bugs and policy mistakes by well-behaved code, not against a malicious module with arbitrary memory read/write. That boundary must be stated in every design decision below; Phase 0 makes the advisory layer *correct*, and Phase 5 defines what actual enforcement would require.

---

## 2. Security audit — findings and remediation

Severity is relative to the project's own stated goals (signed modules, domain isolation, vault confidentiality). "Attacker" below means: a malicious/compromised module binary, or a local process able to write files into module search paths.

### 2.1 Critical — must fix before any new subsystem is built on top

| # | Finding | Location | Why it matters |
|---|---|---|---|
| C1 | **A module can declare `domain = "system"` and receive universal privilege.** `create_module_context()` accepts any manifest domain; no deny-list for reserved domains. During that module's frames, `current_domain()=="system"` bypasses every cross-domain check, vault ownership checks (`check_caller_access`), and `Runtime::get_context` anti-hijack. | `src/core/di_container.cpp:145-148`, `src/core/module_loader.cpp:398-408`, `src/core/vault.cpp:88`, `src/core/registry.cpp:272` | Complete collapse of the isolation model from a one-line manifest change. The developer's own TODO at `di_container.cpp:95` already flags system impersonation. |
| C2 | **Auto-load paths sign binaries with the runtime's own secret key, then "verify" them** — `auto_load_all`, `auto_load_matching`, `auto_load_domain`, `ModuleCatalog::load_all/load_domain`, and the interactive `load` command compute `Crypto::sign_file(key, path)` immediately before `load(name, sig)` whose `signature_override` short-circuits the stored-signature check. | `src/core/module_loader.cpp:609-712`, `src/core/module_catalog.cpp:66-71`, `src/main.cpp:270-278` | Signature enforcement is fully bypassed on every auto-load path: any file dropped into a search path is loaded. |
| C3 | **The master signing key is hardcoded and committed**: `"dvargosh_master_signing_key_2026"` appears in `src/main.cpp:175`, `Makefile` (`sign-modules`), `pipeline_dvargosh/build_pipeline.sh`, and is baked into generated `pipeline_demo_app.cpp` by `generator.py:485`. | build system + runtime | Anyone with repo access can sign arbitrary modules. HMAC-SHA256 with a shared secret is also structurally wrong for code signing (verifier == signer); it detects accidental corruption, not adversaries. |
| C4 | **Any target domain ending in `.*` (or `*`) is callable by any domain, unconditionally.** `check_cross_domain_access()` returns `true` early for `to_domain == "*"` or suffix `".*"`, and `Domain::can_access_domain()` does the same. Since *every* auto-registered method gets domain `<module>.*` (`module.hpp:150-153`, `registry.cpp:100-102`), **cross-domain isolation is void for the entire default surface**. | `src/core/domain.cpp:191-195`, `src/core/domain.cpp:48-57` | The demo "CAUGHT VIOLATION" test only passes because `math.add` is registered under `compute`, not `math.*`; the pipeline-generated surface is not protected. |
| C5 | **Registry aliases take precedence over canonical methods and can be registered by anyone with standard permissions** (`register_alias` has no policy check, no same-provider check, aliases may target other modules' methods). Combined with C4, a module can hijack any call (`alias("math.square" → "evil.fn")`). | `src/core/registry.cpp:172-179, 207` | Method hijacking / shadowing across module boundaries. |
| C6 | **`ExecutionContext::push_frame` is a public, unauthenticated API.** Any in-process module can push a frame claiming `domain="system"` and then legally pass every `current_domain()` check (vault reads/writes, domain-space access). The HMAC frame token only detects out-of-band memory mutation, not API misuse — the salt is a compile-time constant in the binary. | `src/core/execution_context.cpp:16-20`, `:8` | Confirms the advisory nature of the model; must at minimum be moved behind an opaque handle and made host-only. |

**Remediation direction (Phase 0):**

1. Reserved-domain deny-list: refuse to create/attach domains named `system`, `core`, or matching `dvargosh:*` for anything loaded from a dynamic module; keep a single `SecurityContext` object per thread minted by the host.
2. Delete all self-signing call sites (C2). Signature verification uses only `signatures.json` from a *trusted* location, or a key provided out-of-band. Interactive/auto-load runs with `enforce_signatures=false` and prints an explicit banner.
3. Move to **Ed25519 detached signatures** (asymmetric) for modules; keep SHA-256 for integrity. Key lives outside the repo (env/keystore); `sign` becomes a release-engineering step only. Until then, treat signing as checksum.
4. Rework wildcard semantics (C4): `*`/`X.*` must be meaningful only as a *source* pattern (a module's own scope), never as a *target* that automatically grants access. `check_cross_domain_access(from, to)` should match `to` against the caller's explicit allowlist entries only.
5. Alias registration: require the same `provider_module` as the target method, record alias→provider, and resolve canonical methods *before* aliases (or forbid aliases colliding with existing method names entirely).
6. Collapse the frame-push API to `ScopedCallFrame` construction inside `Registry::invoke` only, and mark `push_frame`/`pop_frame` as host-internal (hidden symbol). Document explicitly that in-process tampering is out of scope until Phase 5.

### 2.2 High

| # | Finding | Location |
|---|---|---|
| H1 | **Global `AutoFunctionRegistry` singleton is shared across all statically-linked modules** — the first module calling `register_auto_functions()` registers *every* statically-registered function under its own manifest/policy and then clears the table. Cross-module attribution and permission confusion for static modules. Dynamic (RTLD_LOCAL) modules are insulated by symbol locality; static ones are not. | `include/dvargosh/module.hpp:49-88, 133-203` |
| H2 | **Event handlers execute under the publisher's call frame** — a subscriber's handler invoked while a `system` frame publishes sees `current_domain()=="system"` and inherits universal privilege for nested calls (e.g. vault reads). Handlers should run in the *subscriber's* frame (or an untrusted frame). | `src/core/event_bus.cpp:87-127`, `src/core/vault.cpp:84-90` |
| H3 | **`Runtime::get_context()` resolves module identity by substring match on `dladdr` filename** (`fname.find(name)`, plus underscore-stripped lowercase fallback) — trivially spoofable by naming collision; also falls back to "the only loaded module". | `src/core/runtime.cpp:57-87` |
| H4 | **`ModuleLoader::find_module_file` accepts arbitrary paths** (step 1: `access(path, F_OK)`), and `load_from_file` `dlopen`s *before* header validation — static initializers of a hostile binary execute even when the header later fails validation. Discovery reads headers from file first (good); the load path does not. | `src/core/module_loader.cpp:205-244, 315-354`, `include/dvargosh/module_header.hpp:237-245` |
| H5 | **Unload vs. in-flight invocation race**: `unload_module` destroys the context, unregisters methods, and `dlclose`s while another thread may be inside `Registry::invoke` holding a copied `std::function` whose code lives in the unmapped dylib → use-after-free. Needs a read-write quiescence barrier (active-invocation counter) around unload. | `src/core/module_loader.cpp:525-560`, `src/core/registry.cpp:283-292` |
| H6 | **`ResourceManager::get(id)` / `find_by_name(name)` have no ownership or domain check**, and IDs are sequential — any module can enumerate and use foreign handles (file descriptors etc. once IO lands — this becomes a real hole before Phase 2, so fix it *in* Phase 2). | `src/core/resource_manager.cpp:57-76` |
| H7 | **`DomainManager::create_vault` does not verify the caller owns `config.owner_domain`** — a module can create a vault attributed to a foreign owner domain (confusion / planting), and `Vault::create` accepts any `owner_domain`. | `src/core/domain.cpp:308-325`, `src/core/vault.cpp:11-41` |
| H8 | Vault trust anchors live in ordinary heap (`m_slots` checksums) while payloads sit in guarded memory — an in-process attacker flips both; seal/unseal `mprotect` return codes unchecked (`apply_hardware_protection` sets `m_sealed` unconditionally). | `src/core/vault.cpp:61-66, 184-194` |

### 2.3 Medium / hardening (fix opportunistically)

- `read_module_def_quota_bytes` searches relative fallback paths built from the module name (`modules/<name>/module.def`) — name comes from the module itself; constrain to the binary's own directory. (`module_loader.cpp:14-50`)
- `discover_all_modules`/`load` TOCTOU: signature verified on file A, `dlopen` may open a swapped file; open the file once (fd) and `dlopen` via `/dev/fd` or verify post-open. (Local-attacker only.)
- `TrackedAllocator` quota check-then-allocate is not atomic → slight over-quota under races; acceptable for monitoring, not for enforcement; make it atomic when quotas gain teeth.
- `SecurityPolicy::elevated()` declared but never defined (`permissions.hpp:93`) — remove or implement.
- `registry.cpp` `find_similar_method` runs Levenshtein O(n·m) *under* the registry lock on every miss — cheap self-DoS; compute outside the lock or cap registry size.
- `EventBus::publish` copies handlers then invokes outside the lock — combined with H5's `dlclose`, a concurrent unsubscribe/unload can leave a dangling `std::function`.
- Pipeline codegen interpolates `description`/`ret_type`/`params` into generated C++ without escaping in `generator.py` (the meta-header tool *does* escape via `cpp_escape`/`json.dumps`). A hostile module description containing `\"`/`*/` can inject code into `_generated_registration.cpp` and the interface headers. Route all string interpolation through a single `cpp_escape` helper in the pipeline package.
- `scaffold.py` does not validate `--name` (no `^[a-zA-Z0-9_]+$` check before path construction) — `make new-module NAME='../../x'` writes outside the tree. Validate like `generator.get_module_name`.
- Docker images run as root; CI pins actions by major tag (`@v4`/`@v5`) — pin to commit SHAs; add `USER` to the runner stage.
- Demo secret committed in `development_modules/helloWorld/helloworld_module.cpp:43` (`ROOT_KEY` → `"SECURE_KEY_NAM_CAPTIVES_9988_XYZ"`) — fine for a demo, but keep the pattern of never embedding real secrets in module sources; generate them at load time from a host-provided secret provider instead.
- `build/` is correctly untracked; `signatures.json` is not committed (good). Keep it that way — `signatures.json` in search paths is a trust anchor and must arrive out-of-band.

### 2.4 What the audit does *not* claim

- No findings imply remote exploitability today: there is no network listener, no parser of untrusted input beyond module binaries on local disk.
- The hand-rolled SHA-256/HMAC in `crypto.cpp` is correct against the test vectors shipped and uses constant-time comparison for verification; the recommendation to move to a vetted library (OpenSSL/CommonCrypto/libsodium) is about maintenance risk and Ed25519 availability, not a discovered bug.

---

## 3. Guiding principles for the continuation

1. **Fix the foundation before adding surface.** Phase 0 (Section 2.1 remediation) gates everything: the monitoring/IO/network stacks below all *depend* on correct permission checks; building them on the current wildcard-domain behavior would multiply the attack surface.
2. **Every new capability is a Permission, a quota, and a telemetry stream.** The `Permission` enum already reserves `FileIO`, `NetworkAccess`, `SystemInfo`, `MemoryExpand` — the new stacks slot into the existing model rather than inventing a parallel one. Default is deny; the host ceiling ∩ module manifest intersection rule stays.
3. **Monitoring is a core service, not a module.** The existing `modules/monitor` stays as a *viewer*, but accounting hooks move into the core so they cannot be bypassed by the code they measure.
4. **No hidden state across the ABI.** New core services are exposed through `ModuleContext` (like `registry()`, `allocator()` today), so the pipeline/proxy generation and the module.def permission flow keep working unchanged.
5. **Explicit trust boundary.** Each subsystem doc states what is *enforced* (kernel-assisted: mprotect/mlock/quotas) vs *advisory* (in-process checks). Phase 5 defines the escape hatch for true enforcement.

---

## 4. Target architecture (delta view)

```
                          ┌────────────────────────────────────────────────┐
                          │                  HOST PROCESS                  │
                          │                                                │
  Modules (.dylib/.so)    │  ┌────────────┐   ┌──────────────────────┐     │
 ┌───────────────┐        │  │  Registry  │   │   TelemetryHub       │     │
 │ module A      │──────┐ │  │ (RPC,      │   │  · metric registry   │     │
 │  domain: a.x  │      ├─┼─►│  aliases,  │◄──┤  · ring buffers      │     │
 └───────────────┘      │ │  │  frames)   │   │  · watchdog          │     │
 ┌───────────────┐      │ │  └─────▲──────┘   └──▲──────▲──────▲──────┘     │
 │ module B      │──────┤ │        │             │      │      │            │
 │  domain: b.x  │      │ │  ┌─────┴─────────────┴──────┴──────┴─────┐      │
 └───────────────┘      │ │  │            ModuleContext              │      │
        ▲               │ │  │  registry() telemetry() io() net()    │      │
        │ signed,       │ │  └──┬─────────┬──────────┬───────┬───────┘      │
        │ header-       │ │     │         │          │       │              │
        │ checked       │ │ ┌───▼───┐ ┌───▼────┐ ┌───▼───┐ ┌─▼─────────┐    │
 ┌───────────────┐      │ │ │Memory │ │  IO    │ │  Net  │ │ Execution │    │
 │ ModuleLoader  │──────┼─┼─►Stack  │ │ Stack  │ │ Stack │ │ Stats     │    │
 │  Ed25519 gate │      │ │ │(exists)│ │ (new)  │ │ (new) │ │ (new)     │    │
 └───────────────┘      │ │ └───────┘ └────────┘ └───────┘ └───────────┘    │
                          └────────────────────────────────────────────────┘
                                      │ event bus (telemetry.* topics)
                                      ▼
                          ┌────────────────────┐
                          │ monitor module /   │  dashboards, alerting,
                          │ external exporter  │  quota policy decisions
                          └────────────────────┘
```

---

## 5. Phase 1 — Telemetry & monitoring stacks (next implementation target)

### 5.1 What exists vs. what's missing

`modules/monitor` already demonstrates: a metric map, a memory-occupation report assembled from `TrackedAllocator::get_stats()` and `DomainManager` secured-space walks, event-driven counters, and dashboard RPC. What's missing is (a) **core-side accounting that modules can't skip**, (b) **CPU/time, IO and network dimensions**, (c) **history (ring buffers) and thresholds**, (d) **a watchdog with revocation teeth**.

### 5.2 New core component: `TelemetryHub` (`src/core/telemetry.cpp` + `include/dvargosh/telemetry.hpp`)

A process-wide singleton owned by `DIContainer` (like `Registry`/`EventBus`), exposed on `ModuleContext::telemetry()`.

```cpp
struct MetricSample { uint64_t ts_ns; double value; };

class TelemetryHub {
public:
    // Registration — core stacks call these, modules get read/record APIs gated by SystemInfo.
    MetricStreamId  register_stream(std::string name, MetricStreamConfig cfg);   // capacity, units, aggregation
    void            record(MetricStreamId id, double v);                         // lock-free SPSC ring per stream
    MetricSnapshot  snapshot(std::string_view glob) const;                       // tail read, no allocation on hot path

    // Structured accounting records (memory/IO/net events), emitted by the stacks:
    void            push_event(TelemetryEvent ev);       // bounded MPMC queue, drained by sampler thread

    // Watchdog: thresholds registered by host or admin modules; actions: log, event, throttle, unload
    WatchHandle     watch(std::string stream_glob, ThresholdRule rule, WatchAction action);
};
```

Design rules:

- **Per-stream SPSC ring buffers** (fixed capacity, cache-line aligned `alignas(64)`) — one producer (the accounting point), one consumer (the sampler thread). No allocation on the record path; overflow drops oldest and bumps a `dropped` counter (monitoring must never become the outage).
- **The sampler thread** drains event queues at a fixed tick (default 100 ms), aggregates (rate, p95 via reservoir sampling), evaluates watchdog rules, and publishes `telemetry.snapshot`, `telemetry.threshold_breach` onto the existing `EventBus`. This replaces polling dashboards with push.
- **Accounting is wired at the choke points that already exist:**

| Dimension | Choke point (already in code) | New instrumentation |
|---|---|---|
| Memory | `TrackedAllocator` (per-module, quota'd), `SecuredMemorySpace`, `CommandMemory`, `ArenaAllocator` | emit `mem.alloc`/`mem.free`/`mem.quota_block` events with size+module tag; track `peak`, `current`, `leak_estimate` per module; SecuredMemory bump usage is already exact — export `used/capacity` deltas |
| CPU / time | `Registry::invoke` (`ScopedCallFrame` enter/exit) | measure wall time per invocation → `invoke.duration{method, caller_domain, target_domain}`; per-module cumulative `cpu_ns` (getrusage per-thread delta around frame, documented as advisory in-process) |
| IO (Phase 2 preview) | `ResourceManager` registration/release | every resource open/close/read/write goes through ResourceManager → emit `io.bytes_read/bytes_written/op_count{module, resource_type}` |
| Network (Phase 3 preview) | future `NetStack` (below) | sockets only exist through the stack → `net.bytes_tx/rx, conn.count{module}` per socket |
| Lifecycle | `ModuleLoader` load/unload | `module.load_time_ns`, `module.reload_count`, unload-leak report from `TrackedAllocator::has_leaks()` (already exists) → event instead of stderr |

- **Watchdog actions** are enforced where enforcement is real: memory-quota breach → allocator keeps returning null (already implemented); CPU/runaway breach → a *revocation token* checked in `Registry::invoke`'s frame setup (see below); anything else is alert-only until Phase 2/3 give IO/net real choke points.
- **Revocation token:** extend `SecurityPolicy` with a `std::shared_ptr<const std::atomic<uint32_t>> revocation_epoch`. `Registry::invoke` checks the caller's epoch before dispatch (one relaxed load — cheap enough to keep per-call). Watchdog bumps the epoch on breach → the module's next RPC fails with `PermissionDenied("revoked")`. This is the in-process "kill switch" and also serves Phase 4 (trampoline switch-tables can consult the same token).

### 5.3 Module surface (pipeline-integrated)

- `ModuleContext::telemetry()` returns a `TelemetryHandle` scoped to the module: `record_metric(name, value)` (module-owned namespace `mod.<name>.*`), `snapshot(glob)` (requires `SystemInfo`), `subscribe(glob)` (EventBus already provides).
- New RPC surface on the monitor module (no core changes needed): `monitor.snapshot <glob>`, `monitor.watch <glob> <op> <value>`, `monitor.top` (top-N by cpu_ns, allocations, io). The dashboard commands from `main.cpp` (`memory`, `resources`) migrate to the same snapshot API so CLI and module views are identical.
- Pipeline: add `monitoring` section to `module.def` (`metrics_exported = ...`) and generator support so exported metric names appear in `dvargosh_schema.json` (keeps the lint pipeline authoritative).

### 5.4 Acceptance criteria

1. A module that never calls telemetry still appears in all four dimensions (memory, cpu, io-placeholder, lifecycle) — accounting is in core paths, not opt-in.
2. Sustained `record()` at 1M events/s from 4 threads does not block `Registry::invoke` beyond ±5% (benchmark test).
3. Watchdog unloads (or revokes) a module that breaches a CPU threshold within one sampler tick; test proves invocation fails afterwards.
4. `ctest` additions: `test_telemetry.cpp` (ring overflow, epoch revocation, snapshot consistency), monitor module tests extended.

---

## 6. Phase 2 — IO stack

### 6.1 Design

A core-owned **capability-gated IO layer**, not raw libc passthrough:

```cpp
class IoStack {                                   // exposed as ModuleContext::io()
public:
    Result<IoFile> open(const std::string& virt_path, IoOpenFlags flags);  // requires Permission::FileIO
    Result<size_t> read(IoFile&, void* buf, size_t len);                   // + accounting events
    Result<size_t> write(IoFile&, const void* buf, size_t len);
    Result<void>   close(IoFile&);                                          // ResourceManager::release
};
```

- **Virtual roots per policy**: `SecurityPolicy` gains `std::vector<FsMount> { virtual_path, host_path, read_only }`. A module sees `/data`, `/tmp/<module>` etc.; resolution rejects `..`, symlink escapes (use `openat2`-style semantics — on macOS: resolve+`O_NOFOLLOW`, verify real path stays under the mount), and never exposes the host layout. This is the sandbox that makes `FileIO` meaningful; without it, the permission is a no-op.
- **Every file lives in `ResourceManager`** (fixes H6 first: `get(id)` must verify `owner_module` matches `ExecutionContext::current_module()`). FDs are closed by `cleanup_owner` on unload — leak-proof teardown comes free.
- **Quotas**: per-module `max_open_files`, `max_bytes_written_per_sec` — enforced in the stack, reported through TelemetryHub (`io.*` streams).
- **No `std::fstream` in modules**: the module.def lint (DVARGOSH_LINT) gains a rule; the runtime doesn't ban it (can't), but the stack + docs make the sanctioned path obvious.

### 6.2 Acceptance criteria

Traversal (`/data/../../etc/passwd`, symlink swap between check and open), quota breach, unload-with-open-file, and per-module byte accounting tests all pass; `ResourceInfo` ownership check test passes (H6 closed).

---

## 7. Phase 3 — Networking stack

### 7.1 Design

Same pattern as IO: capability tokens, not raw sockets.

```cpp
class NetStack {                                  // exposed as ModuleContext::net(), requires Permission::NetworkAccess
public:
    Result<NetConn> connect(Endpoint ep, NetOptions opts);   // host allowlist of CIDR/host:port per policy
    Result<void>   send(NetConn&, ConstBuffer);              // + net.bytes_tx accounting
    Result<Buffer> recv(NetConn&, size_t max);               // + net.bytes_rx
    Result<void>   close(NetConn&);                          // ResourceManager-owned lifetime
    Result<NetListener> listen(Endpoint, HandlerFn);         // host-only by default; listener handlers run in
                                                             // an *untrusted* frame (H2 lesson), never publisher's
};
```

- **Policy**: `SecurityPolicy` gains `NetAllowlist { cidrs, ports, protocols }` plus per-module quotas (`max_connections`, `bandwidth_bps` enforced with token buckets fed by TelemetryHub).
- **Event-loop ownership**: the host owns one epoll/kqueue reactor thread; module code never blocks the process — `recv` is async-with-completion (std::function or, better, completion posted back onto the EventBus as `net.<conn>.data`). Synchronous wrappers exist for the demo CLI only.
- **Data exchange with `Value`**: start with `std::vector<uint8_t>`/string payloads; binary ZeroCopy shared pages (the TODO.md idea) is explicitly deferred — it re-opens the in-process trust question and needs the Phase 5 boundary to be safe.
- **TLS**: out of scope for the first cut; the stack is transport-agnostic so a TLS wrapper module (crypto_accelerator domain) can wrap `NetConn` later.
- **Watchdog integration**: connection-count and bandwidth breaches → automatic `close()` + epoch revocation, same mechanism as 5.2.

### 7.2 Acceptance criteria

Connect to non-allowlisted host denied; bandwidth quota enforced and observable; unload with open connections closes them (ResourceManager); listener handler cannot impersonate the listener module (frame test).

---

## 8. Phase 4 — Execution performance track (the TODO.md trampoline plan — positioned deliberately last)

The TODO.md sketches JIT hot-patching: first `invoke()` checks permissions, then patches a call site into an ARM64 `ldr x16, [table]; br x16` trampoline backed by a switch table, keeping module code hashes intact while allowing runtime re-pointing (revocation/hot-reload).

**Assessment: keep the goal (near-native dispatch), change the mechanism.** True code patching on Apple Silicon fights W^X, needs `MAP_JIT` + `pthread_jit_write_protect_np`, `sys_icache_invalidate` synchronization per patch, and produces exactly the "hangs CTest / debuggers blind" failure modes the TODO notes. The same *observable* behavior (first call slow/checked, subsequent calls direct, revocation still possible) is achievable safely:

1. **Direct function-pointer cache in `Registry`**: after first permission-checked invoke, store `DynamicMethodFn` + a `revocation_epoch` snapshot in a per-(caller,method) sharded hash map. Subsequent calls: one atomic epoch load + one hash lookup → direct `fn(args)`. This is the "switch table" as ordinary data — patchable, revocable (epoch mismatch → slow path), no W^X issues.
2. **Devirtualized proxies from the pipeline** (TODO.md's own suggestion): generated `_bind.hpp` already caches `std::function`s — extend to plain function pointers captured at bind time with the epoch token inside the closure. This removes the vtable/std::function overhead without touching code pages.
3. Only if profiling after (1)+(2) shows the remaining frame/token overhead matters: *then* consider writable-executable trampolines under `MAP_JIT`, per-thread, with `sys_icache_invalidate` batching — as a research spike, never as the default path.

**Sequencing note:** this phase must come *after* monitoring (5) because the epoch/revocation token it depends on is introduced there, and after the Phase 0 alias/domain fixes because a fast path must not bypass re-resolved aliases.

---

## 9. Phase 5 — Honest isolation boundary (explicit non-goal for now, stated for direction)

In-process modules with arbitrary code can always: call `push_frame`-equivalents, read/write heap trust anchors, spawn threads, or `dlopen` their own helpers. If Dvargosh ever needs *enforced* isolation for untrusted third parties, the two viable paths are:

- **Out-of-process modules**: same `IModule` ABI over a small IPC shim (Unix domain sockets or Mach ports), with the existing RPC/`Value` serialization crossing the boundary. The registry/event-bus abstractions already support this — the module wouldn't know the difference. Vault/secured-memory semantics degrade to shared-memory segments + SCM_RIGHTS fd passing.
- **WASM-in-the-process** (wasmtime/wamr): compile modules to WASM for untrusted tiers, keep native dylibs for trusted tiers; the Permission model maps naturally to WASI-style capabilities.

Neither is scheduled; recorded here so current design decisions (e.g. "trust anchors in heap are acceptable") are made consciously.

---

## 10. Recommended execution order

| Order | Phase | Gate / why now |
|---|---|---|
| 1 | **Phase 0 — security remediation** (C1–C6, H1–H8) | Everything downstream inherits these rules; cheapest now, most expensive later. Mostly small diffs: deny-lists, delete self-signing, wildcard rework, alias ownership, epoch token. |
| 2 | **Phase 1 — TelemetryHub + watchdog** | Requested next feature; provides revocation + accounting primitives that IO/Net/Phase 4 all consume. |
| 3 | **Phase 2 — IO stack** | Depends on Phase 1 accounting + ResourceManager ownership fix (H6). |
| 4 | **Phase 3 — Networking stack** | Depends on IO-style capability pattern being proven + watchdog teeth. |
| 5 | **Phase 4 — fast dispatch** | Depends on epoch token (P1) and fixed alias/domain semantics (P0). |
| 6 | Phase 5 — enforcement boundary | Explicitly deferred; revisit when third-party untrusted modules become a real use case. |

Each phase lands with: unit tests in `tests/`, schema/lint updates via the pipeline, and a section appended to `docs/architecture.md` so the generated blueprint stays authoritative.
