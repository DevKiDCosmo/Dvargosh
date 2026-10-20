#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

DVARGOSH_EXPORT_FN(accelerator_sha256, "accelerator:hash", "Hardware-accelerated SHA256 simulation") {
    std::string input = args.empty() ? "" : args[0].to_string();
    return Result<Value>::success(Value("ACCEL_HASH_" + Crypto::sha256_hex(input)));
}

} // namespace dvargosh
