#include "dvargosh/dvargosh.hpp"
#include "demo_interfaces.hpp"
#include "../logger/logger_interface.hpp"
#include <iostream>
#include <cstring>

namespace dvargosh {

// Vault Subsystem Implementation
class VaultServiceImpl : public IVaultService {
public:
    explicit VaultServiceImpl(SecuredMemorySpace* space) : m_space(space) {
        if (m_space) {
            char* token = static_cast<char*>(m_space->allocate(64));
            if (token) {
                std::strcpy(token, "SECRET_KEY_VAULT_9948_ALPHA");
                m_token_ptr = token;
            }
        }
    }

    std::string get_secret_token() override {
        return m_token_ptr ? std::string(m_token_ptr) : "EMPTY_VAULT";
    }

    void store_secret(const std::string&, const std::string& secret) override {
        if (m_space && !secret.empty()) {
            char* buf = static_cast<char*>(m_space->allocate(secret.size() + 1));
            if (buf) {
                std::strcpy(buf, secret.c_str());
                m_token_ptr = buf;
            }
        }
    }

private:
    SecuredMemorySpace* m_space = nullptr;
    char* m_token_ptr = nullptr;
};

// Worker Subsystem Implementation
class WorkerServiceImpl : public IWorkerService {
public:
    std::string process_data(const std::string& payload) override {
        return "[TRANSFORMED] " + payload;
    }
};

// Module Root (*) Subsystem Implementation
class ModuleRootServiceImpl : public IModuleRootService {
public:
    std::string get_package_info() override {
        return "demo_pkg v1.0.0 (Domains: main, vault, worker, *)";
    }
};

class DemoPackageModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "demo_pkg";
            m.domain = "*"; // Package root domain
            m.version = Version{1, 0, 0};
            m.description = "Full Demo Package demonstrating Subsystems (Domains) and Inter-Domain Restrictions";
            m.author = "Dvargosh Team";
            m.requested_permissions = PermissionSet::all();
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        DomainManager* dm = ctx.domain_manager();

        // 1. Initialize Subsystems (Domains) inside the module
        if (dm) {
            if (!dm->has_domain("demo_pkg:main")) {
                dm->create_domain("demo_pkg:main", SecurityPolicy::standard());
            }
            if (!dm->has_domain("demo_pkg:vault")) {
                // Initialize vault domain with a dedicated 1MB secured memory container
                dm->create_domain("demo_pkg:vault", SecurityPolicy::strict(), 1024 * 1024, true);
            }
            if (!dm->has_domain("demo_pkg:worker")) {
                dm->create_domain("demo_pkg:worker", SecurityPolicy::standard());
            }

            // 2. Set Domain Restrictions:
            // Vault only permits access from "demo_pkg:main", NOT from "demo_pkg:worker"!
            // In our Domain design, allow_cross_domain(from, to) grants 'from' the right to access 'to':
            dm->allow_cross_domain("demo_pkg:main", "demo_pkg:vault");
            dm->allow_cross_domain("demo_pkg:main", "demo_pkg:worker");
            // NOTE: "demo_pkg:worker" is deliberately NOT granted access to "demo_pkg:vault"!
        }

        // 3. Instantiate Subsystem Services
        SecuredMemorySpace* vault_space = dm ? dm->get_domain_space("demo_pkg:vault") : nullptr;
        m_vault_service = std::make_shared<VaultServiceImpl>(vault_space);
        m_worker_service = std::make_shared<WorkerServiceImpl>();
        m_root_service = std::make_shared<ModuleRootServiceImpl>();

        // 4. Register Services in their Respective Domains
        ctx.register_service<IVaultService>("demo_pkg.vault", m_vault_service, Version{1, 0, 0});
        ctx.register_service<IWorkerService>("demo_pkg.worker", m_worker_service, Version{1, 0, 0});
        ctx.register_service<IModuleRootService>("demo_pkg.root", m_root_service, Version{1, 0, 0});

        // 5. Register Dynamic Methods tagged by Domain:
        // A) Vault Domain Method
        ctx.registry()->register_method(
            "demo_pkg.vault.get_secret",
            "Returns protected secret token from Vault subsystem",
            "demo_pkg",
            "demo_pkg:vault",
            [this](const std::vector<Value>&) -> Result<Value> {
                return Result<Value>::success(Value(m_vault_service->get_secret_token()));
            }
        );

        // B) Worker Domain Method
        ctx.registry()->register_method(
            "demo_pkg.worker.process",
            "Processes data inside Worker subsystem",
            "demo_pkg",
            "demo_pkg:worker",
            [this](const std::vector<Value>& args) -> Result<Value> {
                std::string input = args.empty() ? "sample" : args[0].to_string();
                return Result<Value>::success(Value(m_worker_service->process_data(input)));
            }
        );

        // C) Worker Subsystem attempts to call Vault directly (Should FAIL due to domain restriction)
        ctx.registry()->register_method(
            "demo_pkg.worker.try_vault_violation",
            "Worker tries to access restricted Vault directly (expecting violation)",
            "demo_pkg",
            "demo_pkg:worker",
            [&ctx](const std::vector<Value>&) -> Result<Value> {
                // Call vault as caller domain "demo_pkg:worker"
                auto res = ctx.registry()->invoke(
                    "demo_pkg.vault.get_secret",
                    {},
                    "demo_pkg",
                    "demo_pkg:worker" // Caller is worker!
                );
                return res; // Expecting PermissionDenied
            }
        );

        // D) Main Subsystem orchestrates (Accesses Vault and Worker -> Should SUCCEED)
        ctx.registry()->register_method(
            "demo_pkg.main.orchestrate",
            "Main subsystem accesses Vault and delegates to Worker",
            "demo_pkg",
            "demo_pkg:main",
            [&ctx, this](const std::vector<Value>&) -> Result<Value> {
                // Call vault as caller domain "demo_pkg:main"
                auto vault_res = ctx.registry()->invoke(
                    "demo_pkg.vault.get_secret",
                    {},
                    "demo_pkg",
                    "demo_pkg:main" // Caller is main!
                );
                if (!vault_res.is_ok()) return vault_res;

                std::string token = vault_res.value().to_string();
                std::string processed = m_worker_service->process_data("Job with key " + token);
                return Result<Value>::success(Value(processed));
            }
        );

        // E) Root Wildcard (*) Method
        ctx.registry()->register_method(
            "demo_pkg.root.info",
            "Package root info method (domain: *)",
            "demo_pkg",
            "*",
            [this](const std::vector<Value>&) -> Result<Value> {
                return Result<Value>::success(Value(m_root_service->get_package_info()));
            }
        );

        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override {
        m_vault_service.reset();
        m_worker_service.reset();
        m_root_service.reset();
        return Result<void>::success();
    }

private:
    std::shared_ptr<VaultServiceImpl> m_vault_service;
    std::shared_ptr<WorkerServiceImpl> m_worker_service;
    std::shared_ptr<ModuleRootServiceImpl> m_root_service;
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::DemoPackageModule)
