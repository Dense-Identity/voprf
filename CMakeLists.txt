# CMake minimum version required
cmake_minimum_required(VERSION 3.15)

# -----------------------------------------------------------------------------
# Project Definition
# -----------------------------------------------------------------------------
# Define the project name, version, and language
project(voprf VERSION 1.0.0 LANGUAGES C CXX)

# -----------------------------------------------------------------------------
# C++ Standard Configuration
# -----------------------------------------------------------------------------
# Set the C++ standard to C++17. This ensures that modern language features
# are available. The 'REQUIRED' keyword means CMake will fail if the compiler
# doesn't support C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Avoid compiler-specific extensions (e.g., -gnu++17)

# -----------------------------------------------------------------------------
# Build Options
# -----------------------------------------------------------------------------
# Add an option to build tests, which is ON by default. Users can turn this
# off with `cmake -DBUILD_TESTING=OFF ...` to skip building the test suite.
option(BUILD_TESTING "Build the tests" ON)

# -----------------------------------------------------------------------------
# Subdirectory Processing
# -----------------------------------------------------------------------------
# Add the 'src' directory. CMake will process the CMakeLists.txt file within it,
# which is responsible for building the actual library.
add_subdirectory(src)

# Add the 'examples' directory.
add_subdirectory(examples)

# Only add and configure the 'tests' directory if the BUILD_TESTING option is ON.
if(BUILD_TESTING)
    # This enables the CTest module, which is CMake's testing framework driver.
    enable_testing()
    # Process the CMakeLists.txt file in the 'tests' directory.
    add_subdirectory(tests)
endif()

# -----------------------------------------------------------------------------
# Installation Rules (Optional but good practice)
# -----------------------------------------------------------------------------
# This section defines how to install the library and headers so it can be
# easily used by other projects.

# Install the final library file (e.g., .lib, .so, .a) into the 'lib' directory.
install(TARGETS voprf
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

# Install the public header files.
install(DIRECTORY include/
        DESTINATION include)
