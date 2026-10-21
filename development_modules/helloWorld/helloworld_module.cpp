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
            // 1. Safe space: initialize domain "captives:vault" with 64 KB hardware-guarded secured memory space
            dm->create_domain("captives:vault", SecurityPolicy::strict(), 64 * 1024, true);

            // Store secret key in the safe space
            auto* space = dm->get_domain_space("captives:vault");
            if (space) {
                char* key_buf = static_cast<char*>(space->allocate(64));
                if (key_buf) {
                    std::strcpy(key_buf, "SECURE_KEY_NAM_CAPTIVES_9988_XYZ");
                }
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
