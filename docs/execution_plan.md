# Dvargosh Execution Plan — Secure Dev Environment, Module Integration & Ergonomic Bindings

**Status:** Active plan. Companion to `docs/continuation_architecture.md` (security audit + stack designs) and `docs/architecture.md` (as-built blueprint).
**Date:** 2026-10-26

This plan turns the architecture work into three executable workstreams and a sprint order:

- **WS-A: Secure Development Environment** — make it impossible to merge bad code or secrets quietly ("the perfect environment to code secure code").
- **WS-B: Ergonomic Bindings** — kill the `->invoke("name", {Value(...)})` ceremony on both the export and call sides, with compile-time type safety.
- **WS-C: Networking & IO module integration** — the concrete mechanics for how modules get FileIO/NetworkAccess capabilities, with reference modules.

---

## WS-A — Secure Development Environment

Goal: every `git push` passes through the same hardened gate, and a fresh clone is one command away from a fully instrumented dev loop.

### A1. Build-hardening presets (CMake)

Add `CMakePresets.json` alongside the existing `ENABLE_ASAN` option:

| Preset | Flags | Purpose |
|---|---|---|
| `debug` | `-O0 -g -fno-omit-frame-pointer` | daily driver |
| `sanitize` | ASan + UBSan (existing option) + `-D_GLIBCXX_ASSERTIONS` / on macOS `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE` | memory-safety gate |
| `thread` | `-fsanitize=thread` | race gate (unload vs. invoke, event bus) |
| `hardened-release` | `-O3 -DNDEBUG -fstack-protector-strong -Wl,-z,relro,-z,now -flto` (Linux), `-Wl,-bind_at_load` (macOS) | what ships |
| `fuzz` | `-fsanitize=fuzzer,address` | fuzzing targets |

New Make targets: `make sanitize`, `make threadcheck`, `make hardened`, `make fuzz-smoke`.
Source-level items while touching CMake: build with `-Werror -Wshadow` on CI (keep local builds forgiving), and remove the dead `SecurityPolicy::elevated()` declaration (`permissions.hpp:93`) that currently links cleanly only because nothing calls it.

### A2. Static analysis & formatting

- `.clang-tidy` at repo root, run on the PR diff (fast) and full-tree nightly:

  ```yaml
  Checks: >
    bugprone-*,
    cert-*,
    clang-analyzer-*,
    clang-analyzer-security-*,
    cppcoreguidelines-slicing,
    cppcoreguidelines-pro-type-static-cast-downcast,
    misc-definitions-in-headers,
    performance-*,
    -clang-analyzer-core.NullDereference
  WarningsAsErrors: 'cert-*,clang-analyzer-security-*'
  ```

- `.clang-format` (LLVM base, 4-space indent) + CI format-diff check — ends style debates mechanically.
- New `pipeline_dvargosh/lint.py`: the `DVARGOSH_LINT_001..004` rules in `docs/dvargosh_schema.json` are generated today but enforced nowhere. Make `lint.py` load the schema and fail on `severity: error` (domain naming, secured-memory guard, proxy availability), plus new rules added in WS-B/C. Wire as `make lint` and a CI step.

### A3. Secrets & supply chain

- **Externalize the signing key.** `dvargosh_master_signing_key_2026` is hardcoded in `src/main.cpp:175`, the `Makefile`, `build_pipeline.sh`, and baked into generated code by `generator.py:485`. Replace with: `DVARGOSH_SIGNING_KEY` env var → fallback to a keyfile path → refuse to sign if absent. Dev builds run with `enforce_signatures=false` and print a loud banner; signing happens only in the release script with the key injected by CI secret or local env.
- `.pre-commit-config.yaml` with **gitleaks** (secrets), clang-format, and a "no build artifacts staged" hook. CI runs gitleaks on full history once, then on diffs.
- Pin GitHub Actions to commit SHAs (currently `@v4`/`@v5`); `pip install --require-hashes` from a pinned `requirements.txt` (currently only `rich>=13`); Dockerfile runner stage gets `USER` non-root; add a Trivy/Grype image-scan CI job (fail on High/Critical).
- Add `SECURITY.md` (threat model pointer, private reporting) — required before any public exposure of the repo.

### A4. Fuzzing the untrusted-input surfaces

The runtime already parses attacker-controllable bytes: module binaries and signatures files. Harnesses in `tests/fuzz/` (libFuzzer, run 60s smoke in CI, long runs nightly):

| Harness | Entry point | Why |
|---|---|---|
| `fuzz_module_header` | `ModuleHeader::read_from_file` — magic scan + `from_raw` | walks arbitrary bytes as a packed struct; the single most exposed parser |
| `fuzz_signatures_json` | `load_signatures_from_file` | hand-rolled string-find JSON parser |
| `fuzz_value_roundtrip` | `Value` boxing/unboxing through `AutoMapper::bind` | type-trait conversions |
| `fuzz_registry_invoke` | `Registry::invoke` with random names/args incl. Levenshtein path | protects the lookup-under-lock fix (H-note in audit) |

### A5. CI matrix & definition of done

CI becomes: build (3 compilers) → ctest → **sanitize job → thread job → clang-tidy (diff) → lint.py → gitleaks → fuzz-smoke → docker build+scan**.
**Definition of done for WS-A:** a PR touching `src/` cannot merge without sanitizer-clean tests, tidy-clean diff, lint pass, and zero leaked secrets; a fresh clone gets all of it via `make setup && make secure`.

---

## WS-B — Ergonomic Bindings ("no more `->invoke`")

Three binding surfaces exist today, each half-finished: (1) `DVARGOSH_EXPORT_FN` + a Python codegen that guesses argument unpacking with string heuristics (`if "std::string" in params`, `if "power" in fn_name` — `generator.py:174-190, 317-346`); (2) `AutoMapper::bind<R, Args...>` (client-side, throws on error); (3) typed interface injection `ctx.inject<IMathService>("math")` (works, but see the security caveat below). The plan unifies them around one compile-time core.

### B1. Server side: `ServiceBinder` with signature deduction

New header `include/dvargosh/binder.hpp`. The key idea: **the C++ compiler already knows the function's signature — stop re-parsing it in Python.**

```cpp
// math.services.cpp — functions stay plain, testable C++
double math_add(double a, double b);

// binding: one line per function, anywhere in the module
ctx.bind<&math_add>("add");                       // deduces Result<Value>(double, double) at compile time
ctx.bind<&math_sum_range>("sum_range").desc("Sum 1..n").domain("compute:math");
ctx.bind<&hash_secret>("hash").min_args(1).alias("crypto.hash");
```

Template machinery (~150 lines, C++17):

- `template <auto Fn> BindProxy bind(const char* name)` — deduce `R`/`Args...` via `function_traits`.
- Per-type `Value` traits: `double/int64_t/bool/std::string/std::vector<uint8_t>` both directions; `static_assert` on unsupported types with a readable message ("bind: type X is not Value-convertible") instead of today's silent string coercion.
- Argument-count guard: exact-count check emitted once (replaces `DVARGOSH_EXPORT_REQUIRED_ARGS` bookkeeping and the hand-written `if (args.size() < N)` blocks in generated code).
- Inside, it calls `ctx.register_method(...)` with the module's own policy — same permission flow as today, zero ABI change (it's still a `DynamicMethodFn` in the registry).
- The proxy object is chainable and RAII-nothing: it registers immediately, so partial binding states can't leak.

**What this deletes:** the entire heuristic dispatch block in `generate_registration_cpp` — generated code per function collapses to `ctx.bind<&fn_name>("name");` (or `DVARGOSH_INSTALL_BINDS(...)` aggregating them), which also fixes the escaping/injection issues flagged in the audit §2.3 because the Python side stops embedding parameter logic.

### B2. Client side: generated typed clients v2

Replace today's "everything returns std::string unless the name contains 'power'" proxies with real types, driven by the same parsed signatures:

```cpp
// generated math_api.hpp (client, in headers of the *consumer*)
struct MathApi {
    Result<double> add(21.0, 21.0);                    // Result-returning (explicit)
    double        add_or_throw(21.0, 21.0);            // throwing sugar
};
// usage
auto math = dvargosh::client<MathApi>(ctx);
auto r = math.add(21, 21);                              // Result<double>
```

- Error handling is **Result-first** (matches the codebase's idiom), with `_or_throw` sugar — not the reverse.
- Under the hood the client is a cached `AutoMapper::bind` + the revocation token from TelemetryHub (first call resolves+checks, later calls hit the epoch-checked fast path — this *is* the safe version of the TODO.md switch-table idea).
- Raw `invoke()` remains for dynamic/late-bound use (CLI, scripts); lint rule **DVARGOSH_LINT_005**: "module code must not call `registry()->invoke` directly outside the generated client/binder" (grep-based, enforced by `lint.py`).

### B3. Typed interface injection: keep, but fix three things

`ctx.inject<IMathService>("math")` is already the nicest zero-string path for compile-time-known modules — the pipeline should generate the interface header + registration adapter (`DVARGOSH_SERVICE` marker on a class → `I<Module>Service` + adapter). But the audit surfaced that the current typed path has different security semantics than `invoke`:

1. **`get_service<T>` domain check is conditional** (`registry.hpp:115-140`: skipped when `caller_domain` is empty) — make it unconditional for module callers; empty caller = host-only, resolved via frame, never a bypass.
2. **An injected `shared_ptr<T>` is a permanent, unrevokable capability** — it survives policy changes and (worse) provider unloading: the vtable lives in the provider's dylib, so use after `dlclose` is a UAF (ties to audit H5). Fix: `inject` returns a **weak capability handle** (`ServiceRef<T> { lock()/release() }`) whose `lock()` re-validates domain + provider liveness per call, plus a documented "persistent capability" variant for host code only.
3. **No `DynamicInvoke` check on injection** — require it (same permission the dynamic path needs).

### B4. Pipeline & migration

- Scanner already emits `ret_type`/`params`; generator changes are localized to `generate_registration_cpp` / `generate_typed_interfaces` (delete heuristics, emit binder lines + v2 client).
- Migration is opt-in and mechanical: convert `math`, `logger`, `worker`, `helloWorld` as the four reference implementations (one sprint), keep `DVARGOSH_EXPORT_FN` working for outside contributors.
- New tests: `tests/test_binder.cpp` (type traits, count guard, unsupported-type static_assert), client v2 round-trips, and a compile-fail test harness for the static_asserts.

---

## WS-C — Networking & IO module integration

The stacks themselves are specified in `continuation_architecture.md` §6–§7; this section is the **integration mechanics** — how a module author actually touches IO/net, end to end.

### C1. Capability flow (one sentence per hop)

`module.def` (`permissions = ..., FileIO` / `NetworkAccess`) → `meta_header_tool.py` masks (`PERMISSION_MASKS`, already covers both) → `ModuleHeaderRaw.required_permissions_mask` → runtime manifest → **intersection with host policy ceiling** (`module_loader.cpp:401`) → `ModuleContext::policy()` → checked **on every call** by the new `ctx.io()` / `ctx.net()` facades. Nothing new to invent — the permission plumbing already exists end-to-end; the stacks just become its first real consumers (today `FileIO`/`NetworkAccess` are granted by nothing and enforced by nothing).

### C2. Core facades exposed on ModuleContext

```cpp
// include/dvargosh/io.hpp
class IoStack {  // ctx.io() — requires Permission::FileIO per call
    Result<IoFile> open(vpath, IoOpenFlags);            // policy mounts only: /data, /tmp/<module>
    Result<size_t> read/write(IoFile&, buf, len);       // + telemetry io.bytes_* events
    Result<void>   close(IoFile&);                       // ResourceManager-owned, auto-close on unload
};

// include/dvargosh/net.hpp
class NetStack { // ctx.net() — requires Permission::NetworkAccess per call
    Result<NetConn>    connect(Endpoint);               // policy CIDR/port allowlist + token-bucket bandwidth
    Result<void>       send/recv(...);                  // async completion posted to EventBus: net.<conn>.data
    Result<NetListener> listen(Endpoint, HandlerFn);    // handler runs in an UNTRUSTED frame (audit H2 lesson)
};
```

Both are host-owned singletons on `DIContainer` (like `Registry`), handed to modules as capability-checked facades. `IoFile`/`NetConn` are RAII handles registered in `ResourceManager` **after H6 is fixed** (ownership check in `get(id)`) — unload with open files/sockets closes them via `cleanup_owner`, which already exists.

### C3. What the pipeline generates for the new stacks

- Facade client bindings via the same WS-B machinery: `ctx.bind<&IoStack::open>`-style exports are host-side only; for module *consumption*, the generator emits `io_api.hpp` / `net_api.hpp` thin clients (Result-first, like B2) so module code reads:

  ```cpp
  auto f = ctx.io().open("/data/cache.bin", IoOpenFlags::ReadWrite);
  if (f.is_ok()) f.value().write(bytes);
  auto conn = ctx.net().connect({"tcp", "api.example.com", 443});
  ```

- `scaffold.py --type net|io` templates: a `file_store` module (kv store under its virtual root) and an `http_client` module (allowlist-only fetcher emitting `net.*` metrics) become the reference implementations, wired into `register_standard_modules` with `dev` variants.
- `module.def` gains optional quota keys (`max_open_files`, `max_connections`, `bandwidth_bps`) read by the stacks at context creation; `lint.py` verifies that any module calling `ctx.net()`/`ctx.io()` declares the matching permission (DVARGOSH_LINT_006).

### C4. Telemetry & watchdog integration (why this order matters)

Every read/write/send/recv goes through TelemetryHub streams (`io.bytes_read`, `net.bytes_tx`, …) and the per-module token buckets fed by the sampler thread. Quota breach → bucket empty → the stack's next call fails with `QuotaExceeded` and the watchdog may bump the caller's **revocation epoch** (audit Phase 1 deliverable) — this is the first subsystem where monitoring has real teeth, which is exactly why WS-C is sequenced after TelemetryHub.

### C5. Test strategy (no external network in CI)

- IO: traversal attempts (`/data/../../etc/passwd`, symlink swap), quota breach, unload-with-open-file, ownership check.
- Net: loopback-only integration tests (ephemeral ports, local echo server), allowlist denial, bandwidth token bucket, listener handler frame isolation, unload-closes-sockets.
- Both: sanitizer + thread-sanitizer builds must stay clean — the reactor thread and ring buffers are the first genuinely concurrent core code.

---

## Sprint order (dependency-driven)

| Sprint | Workstream | Deliverable | Gate |
|---|---|---|---|
| **S0** | A1–A5 | Presets, tidy/format/lint/gitleaks/fuzz smoke in CI, key externalized | `make secure` green locally; CI matrix red→green |
| **S1** | Audit Phase 0 | C1–C6 + H1–H8 fixes (continuation doc §2), tests first | all security tests pass under `sanitize` preset |
| **S2** | B1–B4 | `binder.hpp`, generated client v2, 4 reference modules converted, LINT_005 | generated code shrinks; binder tests + fuzz-clean |
| **S3** | TelemetryHub (§5) | `TelemetryHub`, epoch token, watchdog, monitor module v2 | watchdog revocation test; 1M ev/s benchmark |
| **S4** | C (IO) | `IoStack`, mounts policy, H6 ownership fix, `file_store` module | traversal/quota/unload tests green |
| **S5** | C (Net) | `NetStack`, allowlist + bandwidth, reactor thread, `http_client` module | loopback suite green under `thread` preset |
| **S6** | optional | Epoch-cached binder fast path (B2 fast path hardened into product) | benchmark vs. raw invoke; revocation still ≤1 tick |

Rationale for the two ordering decisions that might look surprising:

- **Bindings (S2) before networking (S4/S5):** the net/IO facades and their example modules should be *born* on the ergonomic API — converting them later would be double work, and the binder's compile-time type safety is what makes the facade signatures pleasant.
- **Security fixes (S1) before everything:** the binder registers methods and the stacks check permissions through the exact paths that are currently broken (wildcard domains, alias hijacking, system-domain impersonation). Building on them would bake the flaws in.

---

## First 10 concrete PRs (if starting Monday)

1. `CMakePresets.json` + Make targets (A1) — no code changes.
2. Remove hardcoded signing key; `DVARGOSH_SIGNING_KEY` env flow (A3).
3. `.clang-format` + `.clang-tidy` + pre-commit + gitleaks (A2/A3).
4. `pipeline_dvargosh/lint.py` enforcing existing DVARGOSH_LINT_001–004 (A2).
5. Fuzz harnesses for `read_from_file` + signatures parser (A4).
6. Security fix: reserved-domain deny-list + module `domain="system"` rejection (C1).
7. Security fix: delete self-signing auto-load paths (C2) + Ed25519 design spike doc (C3).
8. Security fix: wildcard target semantics + alias ownership (C4/C5).
9. `include/dvargosh/binder.hpp` + `tests/test_binder.cpp` (B1).
10. Generator: replace heuristic codegen with binder emission (B4) — biggest diff, lands with reference module conversions.
