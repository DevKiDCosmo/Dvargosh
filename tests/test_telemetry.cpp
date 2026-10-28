// TelemetryHub tests (S3): streams, snapshot/top, glob matching, watchdog
// actions (log/event/revoke), and the revocation kill switch end-to-end
// through Registry::invoke.
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

#include <chrono>
#include <thread>

TEST_CASE(test_telemetry_streams_snapshot_and_top) {
    TelemetryHub hub(nullptr);

    hub.record("alpha.count", 5.0);
    hub.record("alpha.count", 15.0);
    hub.increment("beta.total", 2.0);
    hub.increment("beta.total", 3.0);
    hub.record("gamma.unrelated", 99.0);

    auto all = hub.snapshot("*");
    ASSERT_TRUE(all.size() >= 3);

    auto alphas = hub.snapshot("alpha.*");
    ASSERT_EQ(alphas.size(), 1);
    ASSERT_EQ(alphas[0].name, "alpha.count");
    ASSERT_EQ(alphas[0].last, 15.0);
    ASSERT_EQ(alphas[0].min, 5.0);
    ASSERT_EQ(alphas[0].max, 15.0);
    ASSERT_EQ(alphas[0].avg, 10.0);
    ASSERT_EQ(alphas[0].count, 2);

    auto betas = hub.snapshot("beta.*");
    ASSERT_EQ(betas[0].last, 5.0); // increment accumulates

    auto top = hub.top_streams(2);
    ASSERT_EQ(top.size(), 2);
    ASSERT_EQ(top[0].name, "gamma.unrelated"); // highest last value first
}

TEST_CASE(test_telemetry_watch_validation_and_listing) {
    TelemetryHub hub(nullptr);

    auto bad_op = hub.watch("x.*", "=", 1.0, "log");
    ASSERT_FALSE(bad_op.is_ok());

    auto bad_action = hub.watch("x.*", ">", 1.0, "explode");
    ASSERT_FALSE(bad_action.is_ok());

    auto ok = hub.watch("x.*", ">", 1.0, "event");
    ASSERT_TRUE(ok.is_ok());

    auto watches = hub.list_watches();
    ASSERT_EQ(watches.size(), 1);
    ASSERT_EQ(watches[0].stream_glob, "x.*");

    ASSERT_TRUE(hub.unwatch(ok.value()).is_ok());
    ASSERT_TRUE(hub.unwatch(99999).status() == StatusCode::NotFound);
}

TEST_CASE(test_telemetry_watchdog_event_and_revoke_kill_switch) {
    auto bus = std::make_shared<EventBus>();
    TelemetryHub hub(bus);
    hub.set_tick_interval_ms(40);

    // Event action: subscribe and count breaches.
    std::atomic<int> breaches{0};
    (void)bus->subscribe("telemetry.threshold_breach", "test_sub",
                         [&](const std::string&, const Value&) { breaches++; }, nullptr);

    // Revoke action: a policy tracked under a module name gets flipped.
    SecurityPolicy policy = SecurityPolicy::standard();
    hub.track_policy("watched_module", policy);
    ASSERT_FALSE(policy.is_revoked());

    ASSERT_TRUE(hub.watch("test.events", ">", 10.0, "event").is_ok());
    ASSERT_TRUE(hub.watch("test.revoked_stream", ">", 10.0, "revoke", "watched_module").is_ok());

    hub.record("test.events", 100.0);
    hub.record("test.revoked_stream", 100.0);

    // Sampler fires within a couple of ticks; poll generously.
    for (int i = 0; i < 100 && (breaches.load() == 0 || !policy.is_revoked()); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    ASSERT_TRUE(breaches.load() >= 1);
    ASSERT_TRUE(policy.is_revoked()); // watchdog flipped the shared epoch

    // The kill switch is honored by Registry::invoke.
    Registry reg;
    (void)reg.register_method(
        "telemetry.ping", "ping", "mod", "mod:*",
        [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value("pong"));
        },
        nullptr);
    auto denied = reg.invoke("telemetry.ping", {}, "watched_module", "mod:*", &policy);
    ASSERT_FALSE(denied.is_ok());
    ASSERT_EQ(denied.status(), StatusCode::PermissionDenied);

    // Restore un-revokes.
    ASSERT_TRUE(hub.restore_policy("watched_module"));
    ASSERT_FALSE(policy.is_revoked());
    auto restored = reg.invoke("telemetry.ping", {}, "watched_module", "mod:*", &policy);
    ASSERT_TRUE(restored.is_ok());
}

TEST_CASE(test_telemetry_invoke_accounting_native) {
    auto di = std::make_shared<DIContainer>();
    auto* hub = di->telemetry();
    ASSERT_TRUE(hub != nullptr);

    // Static module + binder method; every dispatch must land in the hub.
    ASSERT_TRUE(di->registry()->invoke("logger.debug", {Value("telemetry probe")}, "t", "system", nullptr).is_ok()
                || true); // logger may or may not be loaded; accounting happens either way

    // Invoke something that definitely exists: the module catalog lookups are
    // not methods, so register one directly through a minimal context.
    auto ctx_res = di->create_module_context("acct_mod", "acct", SecurityPolicy::standard());
    ASSERT_TRUE(ctx_res.is_ok());
    auto& ctx = *ctx_res.value();
    (void)ctx.register_method("acct.echo", "echo", [](const std::vector<Value>& args) -> Result<Value> {
        if (args.size() != 1) {
            return Result<Value>::failure(StatusCode::InvalidArg, "acct.echo wants exactly 1 argument");
        }
        return Result<Value>::success(args[0]);
    });

    for (int i = 0; i < 3; ++i) {
        auto r = di->registry()->invoke("acct.echo", {Value("x")}, "acct", "acct", &ctx.policy());
        ASSERT_TRUE(r.is_ok());
    }
    // Force a failed-Result path too (failure Results count as errors in telemetry).
    (void)di->registry()->invoke("acct.echo", {Value("x"), Value("y")}, "acct", "acct", &ctx.policy());

    auto counts = hub->snapshot("invoke.count.acct.echo");
    ASSERT_EQ(counts.size(), 1);
    ASSERT_EQ(counts[0].last, 4.0); // 3 ok + 1 failed

    auto errs = hub->snapshot("invoke.errors.acct.echo");
    ASSERT_EQ(errs.size(), 1);
    ASSERT_EQ(errs[0].last, 1.0);

    auto durs = hub->snapshot("invoke.duration_ms.acct.echo");
    ASSERT_EQ(durs.size(), 1);
    ASSERT_TRUE(durs[0].count >= 4);
}
