cmake_minimum_required(VERSION 3.20)
project(AISandbox VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

add_subdirectory(common)
add_subdirectory(launcher)
add_subdirectory(tests)

# test_restrict is Windows-specific (tests Restricted Token API)
if(WIN32)
    add_subdirectory(test_restrict)
endif()
