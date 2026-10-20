#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

// Direct native C++ function decorated with attribution macro:
// The preprocessor expands DVARGOSH_SERVICE to an annotation or no-op at compile time.
// The pipeline scanner parses this marker, generates the registration bridge and typed proxy.
DVARGOSH_SERVICE(accelerator:hash)
std::string accelerator_sha256(const std::string& input) {
    return "ACCEL_HASH_" + Crypto::sha256_hex(input);
}

} // namespace dvargosh
