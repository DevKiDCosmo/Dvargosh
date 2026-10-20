#pragma once

#include <string>

namespace dvargosh {

class IVaultService {
public:
    virtual ~IVaultService() = default;
    virtual std::string get_secret_token() = 0;
    virtual void store_secret(const std::string& key, const std::string& secret) = 0;
};

class IWorkerService {
public:
    virtual ~IWorkerService() = default;
    virtual std::string process_data(const std::string& payload) = 0;
};

class IModuleRootService {
public:
    virtual ~IModuleRootService() = default;
    virtual std::string get_package_info() = 0;
};

} // namespace dvargosh
