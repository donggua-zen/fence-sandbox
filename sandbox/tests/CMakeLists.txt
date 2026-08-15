# Integration tests for sandbox
# Run with: ctest --output-on-failure

if(WIN32)
    add_test(NAME integration_tests
        COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_windows.bat" "$<TARGET_FILE:sandbox>"
    )
else()
    add_test(NAME integration_tests
        COMMAND bash "${CMAKE_CURRENT_LIST_DIR}/test_linux.sh" "$<TARGET_FILE:sandbox>"
    )
endif()
