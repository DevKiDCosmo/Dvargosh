#include "test_framework.hpp"
#include "dvargosh/permissions.hpp"

using namespace dvargosh;

TEST_CASE(test_permission_bitmask) {
    PermissionSet set;
    ASSERT_FALSE(set.has(Permission::FileIO));
    ASSERT_FALSE(set.has(Permission::NetworkAccess));

    set.grant(Permission::FileIO);
    ASSERT_TRUE(set.has(Permission::FileIO));
    ASSERT_FALSE(set.has(Permission::NetworkAccess));

    set.grant(Permission::NetworkAccess);
    ASSERT_TRUE(set.has(Permission::FileIO));
    ASSERT_TRUE(set.has(Permission::NetworkAccess));

    set.revoke(Permission::FileIO);
    ASSERT_FALSE(set.has(Permission::FileIO));
    ASSERT_TRUE(set.has(Permission::NetworkAccess));
}

TEST_CASE(test_security_policy_enforcement) {
    SecurityPolicy policy;
    policy.permissions().grant(Permission::ServiceRegister);
    policy.permissions().revoke(Permission::DynamicInvoke);

    ASSERT_TRUE(policy.check(Permission::ServiceRegister, "mod_test").is_ok());

    auto denied = policy.check(Permission::DynamicInvoke, "mod_test");
    ASSERT_FALSE(denied.is_ok());
    ASSERT_EQ(denied.status(), StatusCode::PermissionDenied);
}
