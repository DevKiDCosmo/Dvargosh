#include "dvargosh/dvargosh.hpp"
#include <iostream>
#include <cstring>

namespace dvargosh {

class HelloWorldModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "hello_world";
            m.domain = "*";
            m.version = Version{1, 0, 0};
            m.description = "Hello World module with hardware-guarded safe space and domain isolation";
            m.author = "I am Nam";
            m.requested_permissions = PermissionSet::all();
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        DomainManager* dm = ctx.domain_manager();
        if (dm) {
            // 1. Safe space: initialize domain "captives:vault" with strict policy
            dm->create_domain("captives:vault", SecurityPolicy::strict(), 64 * 1024, true);

            // Create high-security cryptographic Vault inside "captives:vault"
            VaultConfig vcfg;
            vcfg.name = "captives_vault";
            vcfg.owner_domain = "captives:vault";
            vcfg.owner_module = "hello_world";
            vcfg.capacity_bytes = 64 * 1024;
            vcfg.security_level = VaultSecurityLevel::TamperProof;
            vcfg.use_guard_pages = true;
            vcfg.auto_seal_on_write = true;
            vcfg.description = "Hardware-guarded high-security cryptographic vault storing root captives tokens.";

            auto vault_res = dm->create_vault(vcfg);
            if (vault_res.is_ok()) {
                // Safely write the secret key into the sealed vault
                vault_res.value()->write_secret("ROOT_KEY", "SECURE_KEY_NAM_CAPTIVES_9988_XYZ");
            }

            // 2. Intruder domain: "captives:intruder" with NO access granted to "captives:vault"
            dm->create_domain("captives:intruder", SecurityPolicy::strict());

            // 3. Normal domain: "captives:hello_world"
            dm->create_domain("captives:hello_world", SecurityPolicy::standard());
        }

        register_auto_functions(ctx);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::HelloWorldModule)
