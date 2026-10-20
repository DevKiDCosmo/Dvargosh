#include "dvargosh/dvargosh.hpp"

namespace dvargosh {

class CryptoAcceleratorModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "crypto_accelerator";
            m.domain = "*";
            m.version = Version{1, 0, 0};
            m.description = "Experimental Cryptographic Accelerator Module with Non-Monolithic Auto-Registered Functions";
            m.author = "Dvargosh Dev Team";
            m.requested_permissions = PermissionSet::all();
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        // Automatically registers functions declared in hasher.cpp and cipher.cpp
        register_auto_functions(ctx);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::CryptoAcceleratorModule)
