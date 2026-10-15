cmake_minimum_required(VERSION 3.20)
project(AISandbox VERSION 1.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to a widely compatible macOS deployment target. Without this, CMake
# inherits the build machine's OS version, so a binary built on a current CI
# runner would refuse to launch on older macOS — which affects Intel Macs in
# particular, since they are common on older releases. The Darwin platform
# init may leave the cache entry present but empty, hence the value check and
# FORCE (a non-empty user/env value is never touched).
if(APPLE AND NOT CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum supported macOS version" FORCE)
endif()

enable_testing()

add_subdirectory(common)
add_subdirectory(launcher)
add_subdirectory(tests)

# test_restrict is Windows-specific (tests Restricted Token API)
if(WIN32)
    add_subdirectory(test_restrict)
endif()
