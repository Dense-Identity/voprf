# -----------------------------------------------------------------------------
# Library Target Definition
# -----------------------------------------------------------------------------
# Define the library target. Let's name it 'voprf'.
# It will be built from the specified source files.
add_library(voprf
    voprf.cpp
    # Add any other internal .cpp files here
    # e.g., internal_utils.cpp
)

# -----------------------------------------------------------------------------
# Include Directories
# -----------------------------------------------------------------------------
# This is a crucial step. It tells the compiler where to find header files.
# `target_include_directories` is the modern way to manage includes.

# PUBLIC: Any target that links against 'voprf' will automatically get this
# include directory. This is how we expose the public API headers.
# `${PROJECT_SOURCE_DIR}` refers to the root directory of the project.
target_include_directories(voprf
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include> # Path when installed
)

# PRIVATE: For internal headers within the 'src' directory. These are needed
# to compile 'voprf' itself but are not exposed to consumers of the library.
target_include_directories(voprf
    PRIVATE
        . # The current directory ('src')
)

# -----------------------------------------------------------------------------
# Dependencies (Example)
# -----------------------------------------------------------------------------
# If you were using an external library like MCL, you would find it and link it here.
# For example:
find_package(MCL REQUIRED)
target_link_libraries(voprf PRIVATE MCL::mcl)
