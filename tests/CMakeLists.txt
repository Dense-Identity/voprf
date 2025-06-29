# -----------------------------------------------------------------------------
# Test Executable Definition
# -----------------------------------------------------------------------------
# Define an executable for our test suite.
add_executable(run_voprf_tests
    test_voprf.cpp
)

# -----------------------------------------------------------------------------
# Link Libraries
# -----------------------------------------------------------------------------
# Link the test executable against our 'voprf' library so it can call its functions.
target_link_libraries(run_voprf_tests
    PRIVATE
        voprf
)

# -----------------------------------------------------------------------------
# Test Framework Integration (Example with GTest)
# -----------------------------------------------------------------------------
# If using a test framework like GoogleTest, you would find it and link it.
# You would typically add GTest via FetchContent in the top-level CMakeLists.txt
# and then link it here.
#
# find_package(GTest REQUIRED)
# target_link_libraries(run_voprf_tests PRIVATE GTest::gtest_main)

# -----------------------------------------------------------------------------
# Add Test to CTest
# -----------------------------------------------------------------------------
# This command registers the executable with CTest. Now you can run the tests
# by simply running `ctest` from your build directory.
add_test(NAME VoprfTests COMMAND run_voprf_tests)
