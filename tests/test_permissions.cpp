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

TEST_CASE(test_permission_set_intersection) {
    PermissionSet setA({Permission::FileIO, Permission::NetworkAccess, Permission::ServiceRegister});
    PermissionSet setB({Permission::NetworkAccess, Permission::SecuredMemory});

    PermissionSet inter = setA.intersect_with(setB);
    ASSERT_TRUE(inter.has(Permission::NetworkAccess));
    ASSERT_FALSE(inter.has(Permission::FileIO));
    ASSERT_FALSE(inter.has(Permission::ServiceRegister));
    ASSERT_FALSE(inter.has(Permission::SecuredMemory));

    // Intersecting strict (empty) permissions with all() MUST remain strictly empty
    PermissionSet strict_set = PermissionSet::none();
    PermissionSet all_set = PermissionSet::all();
    PermissionSet result = strict_set.intersect_with(all_set);
    ASSERT_FALSE(result.has(Permission::FileIO));
    ASSERT_FALSE(result.has(Permission::NetworkAccess));
    ASSERT_FALSE(result.has(Permission::ServiceRegister));
    ASSERT_FALSE(result.has(Permission::Admin));
}
