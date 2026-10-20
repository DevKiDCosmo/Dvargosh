#include "dvargosh/dvargosh.hpp"
#include <iostream>

namespace dvargosh {

class HelloWorldModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "hello_world";
            m.domain = "*";
            m.version = Version{1, 0, 0};
            m.description = "Hello World";
            m.author = "I am Nam";
            m.requested_permissions = PermissionSet::all();
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        register_auto_functions(ctx);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { 
        // std::cout << "YOU DESTROYED THE MODULE, YOU DAEMON!" << std::endl;
        // // Reform to invoke more easily through a global container
        // auto di = std::make_shared<DIContainer>();
        // auto mem_res = di->registry()->invoke("logger.log", {Value("YOU DESTROYED THE MODULE, YOU DAEMON!")});
        return Result<void>::success(); 
    }
    Result<void> on_unload(ModuleContext&) override { 
        // std::cout << "YOU KILLED THE MODULE, YOU DAEMON!" << std::endl;
        return Result<void>::success();
    }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::HelloWorldModule)
