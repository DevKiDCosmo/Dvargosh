#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

// Automatic function registration in a non-monolithic source file using DVARGOSH_EXPORT_FN
DVARGOSH_EXPORT_FN(demo_pkg_vault_hash, "demo_pkg:vault", "Auto-registered SHA256 hashing function in vault subsystem") {
    std::string text = args.empty() ? "" : args[0].to_string();
    std::string hashed = Crypto::sha256_hex(text);
    return Result<Value>::success(Value(hashed));
}
DVARGOSH_EXPORT_ALIAS_OVERRIDE(demo_pkg_vault_hash, "demo_pkg.demo_pkg_vault_hash");

} // namespace dvargosh
