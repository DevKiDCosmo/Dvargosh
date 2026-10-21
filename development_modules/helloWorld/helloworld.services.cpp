#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

DVARGOSH_SERVICE(captives:hello_world)
std::string hello_world(const std::string& input) {
    return "HELLO_WORLD_" + input;
}

DVARGOSH_SERVICE(captives:hello_world)
std::string invokeothers() {
    // invoke monitor.get
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    auto hash_res = di->registry()->invoke("demo_pkg_vault_hash", {Value("DvargoshData")});
    return hash_res.is_ok() ? hash_res.value().to_string() : "Error";
}


} // namespace dvargosh
