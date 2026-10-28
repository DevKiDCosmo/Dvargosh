#pragma once

// ============================================================================
// DEMO / TEST HARNESS SIGNING UTILITY — NOT FOR PRODUCTION USE
// ============================================================================
// Audit C2 removed self-signing from the loader and catalog: the runtime only
// VERIFIES. Harnesses that exercise the sign→verify machinery (the demo binary,
// dvargosh_app_loader_test, the generated pipeline app) play both roles and use
// this helper to provision a signatures.json trust anchor from a key they hold.
// Production distribution signing happens out-of-band (make sign-modules / CI).

#include "dvargosh/crypto.hpp"
#include "dvargosh/module_loader.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace dvargosh {

inline void provision_signatures_for_demo(
    const ModuleLoader& loader,
    const std::string& key,
    const char* label = "[demo]"
) {
    for (const auto& dir : loader.search_paths()) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) continue;

        std::ostringstream json;
        json << "{";
        bool first = true;
        size_t count = 0;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            const auto& p = entry.path();
            std::string ext = p.extension().string();
            if (ext != ".dylib" && ext != ".so") continue;
            auto sig = Crypto::sign_file(key, p.string());
            if (!sig.is_ok()) continue;
            if (!first) json << ",";
            json << "\"" << p.filename().string() << "\": {\"hmac_sha256\": \"" << sig.value() << "\"}";
            first = false;
            count++;
        }
        json << "}";

        const auto out = std::filesystem::path(dir) / "signatures.json";
        std::ofstream(out.string()) << json.str();
        std::cout << label << " Provisioned " << out.string() << " (" << count << " signatures)\n";
        return; // one trust anchor is enough; discovery pre-loads from all search paths
    }
    std::cerr << label << " [WARN] No writable search path found for signatures.json\n";
}

} // namespace dvargosh
