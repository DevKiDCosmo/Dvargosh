cmake_minimum_required(VERSION 3.16)
project(Dvargosh VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler Warnings & Flags
if(MSVC)
    add_compile_options(/W4 /EHsc)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Sanitizers (ASan, UBSan)
option(ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ENABLE_ASAN)
    if(NOT MSVC)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/modules)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find Threads and DL libraries
find_package(Threads REQUIRED)
set(EXTRA_LIBS ${CMAKE_DL_LIBS} Threads::Threads)

# Include directories
include_directories(include)

# Core Library Sources
set(CORE_SOURCES
    src/core/crypto.cpp
    src/core/permissions.cpp
    src/core/secured_memory.cpp
    src/core/allocator.cpp
    src/core/resource_manager.cpp
    src/core/event_bus.cpp
    src/core/domain.cpp
    src/core/registry.cpp
    src/core/di_container.cpp
    src/core/module_loader.cpp
    src/core/module_catalog.cpp
    src/core/runtime.cpp
    src/core/execution_context.cpp
    src/core/command_memory.cpp
    src/core/vault.cpp
)

add_library(dvargosh_core SHARED ${CORE_SOURCES})
target_link_libraries(dvargosh_core PUBLIC ${EXTRA_LIBS})
target_include_directories(dvargosh_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Include Auto-generated Module Targets (generated in build/generated/)
if(EXISTS "${CMAKE_BINARY_DIR}/generated/Modules.cmake")
    include(${CMAKE_BINARY_DIR}/generated/Modules.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/modules/Modules.cmake")
    include(modules/Modules.cmake)
endif()

if(EXISTS "${CMAKE_BINARY_DIR}/generated/DevModules.cmake")
    include(${CMAKE_BINARY_DIR}/generated/DevModules.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/development_modules/DevModules.cmake")
    include(development_modules/DevModules.cmake)
elseif(EXISTS "${CMAKE_BINARY_DIR}/development_modules/DevModules.cmake")
    include(${CMAKE_BINARY_DIR}/development_modules/DevModules.cmake)
endif()

set(ALL_MODULES_LIST ${DVARGOSH_MODULES_TARGETS} ${DVARGOSH_ALL_MODULE_TARGETS} ${DVARGOSH_DEVELOPMENT_MODULES_TARGETS})

# Main Executable / Demo CLI
add_executable(dvargosh src/main.cpp)
target_link_libraries(dvargosh PRIVATE dvargosh_core)
target_include_directories(dvargosh PRIVATE include ${CMAKE_BINARY_DIR}/generated/include)
if(ALL_MODULES_LIST)
    add_dependencies(dvargosh ${ALL_MODULES_LIST})
endif()

# Standalone App Test (load('name', 'signature'))
add_executable(dvargosh_app_loader_test src/app/loader.test.cpp)
target_link_libraries(dvargosh_app_loader_test PRIVATE dvargosh_core)
target_include_directories(dvargosh_app_loader_test PRIVATE include ${CMAKE_BINARY_DIR}/generated/include)
if(ALL_MODULES_LIST)
    add_dependencies(dvargosh_app_loader_test ${ALL_MODULES_LIST})
endif()

# Pipeline Auto-Generated Demo App (Direct Typed Interface Calls)
if(EXISTS "${CMAKE_BINARY_DIR}/generated/src/pipeline_demo_app.cpp")
    add_executable(dvargosh_pipeline_app ${CMAKE_BINARY_DIR}/generated/src/pipeline_demo_app.cpp)
    target_link_libraries(dvargosh_pipeline_app PRIVATE dvargosh_core)
    target_include_directories(dvargosh_pipeline_app PRIVATE include ${CMAKE_BINARY_DIR}/generated/include)
    if(ALL_MODULES_LIST)
        add_dependencies(dvargosh_pipeline_app ${ALL_MODULES_LIST})
    endif()
endif()

# Test Suite
enable_testing()

set(CORE_TEST_SOURCES
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_permissions.cpp
    tests/test_secured_memory.cpp
    tests/test_registry_di.cpp
    tests/test_module_lifecycle.cpp
    tests/test_violations.cpp
    tests/test_domains.cpp
    tests/test_isolation_and_secure_memory.cpp
)

set(MODULE_TEST_SOURCES
    modules/logger/test/test_logger.cpp
    modules/math/test/test_math.cpp
    modules/worker/test/test_worker.cpp
    modules/monitor/test/test_monitor.cpp
    modules/demo_pkg/test/test_demo_pkg.cpp
)

add_executable(dvargosh_tests ${CORE_TEST_SOURCES} ${MODULE_TEST_SOURCES})
target_link_libraries(dvargosh_tests PRIVATE dvargosh_core)
target_include_directories(dvargosh_tests PRIVATE include tests modules)
if(ALL_MODULES_LIST)
    add_dependencies(dvargosh_tests ${ALL_MODULES_LIST})
endif()

add_test(NAME UnitTests COMMAND $<TARGET_FILE:dvargosh_tests>)
add_test(NAME AppLoaderTest COMMAND $<TARGET_FILE:dvargosh_app_loader_test>)
add_test(NAME IntegrationDemo COMMAND $<TARGET_FILE:dvargosh> --modules ${CMAKE_BINARY_DIR}/modules)
if(TARGET dvargosh_pipeline_app)
    add_test(NAME PipelineGeneratedApp COMMAND $<TARGET_FILE:dvargosh_pipeline_app>)
endif()
