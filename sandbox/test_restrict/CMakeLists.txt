# Restricted Token test program
add_executable(test_restricted main.cpp)

set_target_properties(test_restricted PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
)

target_link_libraries(test_restricted PRIVATE advapi32.lib)
target_compile_options(test_restricted PRIVATE /W4 /Zi /Gy /Gm- /utf-8)
