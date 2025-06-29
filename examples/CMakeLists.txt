# -----------------------------------------------------------------------------
# Example Executable Definition
# -----------------------------------------------------------------------------
# Define an executable for the example usage program.
add_executable(basic_usage
    basic_usage.c
)

# -----------------------------------------------------------------------------
# Link Libraries
# -----------------------------------------------------------------------------
# Link the example against the 'voprf' library, just as a real user would.
target_link_libraries(basic_usage
    PRIVATE
        voprf
)
