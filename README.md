VOPRF-C: A Lightweight C Library for VOPRFVOPRF-C is a minimal, portable C library that implements the Verifiable Oblivious Pseudorandom Function (VOPRF) protocol as specified in RFC 9497. It is built with a clean C-style API, making it easy to use directly in C/C++ projects or to create bindings for other programming languages.This implementation uses a pairing-based construction to achieve the "verifiable" property.FeaturesC-Style API: Clean, simple C functions for maximum portability and ease of creating bindings.Minimal Dependencies: Relies on a standard C/C++ compiler and CMake. The underlying cryptography is provided by the MCL pairing library.Memory Safe: Clear API for memory allocation and deallocation. No hidden memory management.Verifiable: Implements the VOPRF protocol, allowing clients to verify the correctness of the server's evaluation.Building the LibraryPrerequisitesA C++17 compatible compiler (e.g., GCC, Clang, MSVC).CMake (version 3.15 or later).The MCL library must be installed and findable by CMake.Build StepsYou can build the library using standard CMake commands:# 1. Clone the repository
git clone https://your-repository-url/voprf-c.git
cd voprf-c

# 2. Create a build directory
mkdir build && cd build

# 3. Configure the project with CMake
#    -DBUILD_TESTING=OFF can be used to skip building tests
cmake ..

# 4. Compile the library
make
# On Windows, you might use: cmake --build .

# 5. (Optional) Install the library system-wide
#    You may need sudo for this step
make install
This will produce a static library (libvoprf.a) and/or a shared library (libvoprf.so or voprf.dll) in the build/src/ directory, and install them to a standard location if make install is run.API Usage GuideUsing the library involves including the main header, initializing the library, creating and managing objects, and calling the protocol functions.LinkingTo use the library in your own project, you need to include the header and link against the compiled library file.#include <voprf/voprf.h>
Example GCC command:# Assuming libvoprf.a is in ../build/src and voprf.h is in ../include
gcc my_app.c -I../include -L../build/src -lvoprf -o my_app
Core ConceptsError Handling: All functions return an int status code. 0 (VOPRF_SUCCESS) indicates success. A negative value indicates an error.Opaque Pointers: All objects (keys, points) are managed through opaque pointers (e.g., voprf_private_key_t*). You cannot access their internal data directly.Memory Management: For every object created (e.g., with voprf_private_key_generate or _from_bytes), you are responsible for calling its corresponding _destroy function (e.g., voprf_private_key_destroy) to prevent memory leaks.Full Example WalkthroughHere is a complete example demonstrating the entire VOPRF protocol flow.// examples/main.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <voprf/voprf.h>

void check_status(int status, const char* step) {
    if (status != 0) {
        fprintf(stderr, "Error during step '%s': %d\n", step, status);
        exit(1);
    }
}

int main() {
    int status;
    printf("--- VOPRF Protocol Simulation ---\n");

    // 1. GLOBAL: Initialize the library (MUST be called once)
    status = voprf_init();
    check_status(status, "voprf_init");
    printf("[OK] Library initialized.\n");

    // 2. SERVER-SIDE: Generate a key pair
    voprf_private_key_t* server_sk = NULL;
    voprf_public_key_t* server_pk = NULL;

    status = voprf_private_key_generate(&server_sk);
    check_status(status, "server key generation");

    status = voprf_private_key_get_public_key(server_sk, &server_pk);
    check_status(status, "get public key");
    printf("[OK] Server key pair generated.\n");

    // 3. CLIENT-SIDE: Prepare input and blind it
    const char* message = "my secret message";
    voprf_private_key_t* blinding_factor = NULL;
    voprf_point_t* blinded_point = NULL;

    status = voprf_blind(
        (const uint8_t*)message,
        strlen(message),
        &blinding_factor,
        &blinded_point
    );
    check_status(status, "client blind");
    printf("[OK] Client blinded the message.\n");

    // --> In a real application, the client sends `blinded_point` to the server.

    // 4. SERVER-SIDE: Evaluate the blinded point
    voprf_point_t* evaluated_point = NULL;
    status = voprf_evaluate(server_sk, blinded_point, &evaluated_point);
    check_status(status, "server evaluate");
    printf("[OK] Server evaluated the point.\n");

    // --> The server sends `evaluated_point` back to the client.

    // 5. CLIENT-SIDE: Unblind the result to get the final OPRF output
    voprf_point_t* final_output = NULL;
    status = voprf_unblind(evaluated_point, blinding_factor, &final_output);
    check_status(status, "client unblind");
    printf("[OK] Client unblinded the result.\n");

    // 6. VERIFICATION: Anyone can verify the output
    bool is_valid = false;
    status = voprf_verify(
        server_pk,
        (const uint8_t*)message,
        strlen(message),
        final_output,
        &is_valid
    );
    check_status(status, "verification");
    assert(is_valid == true);
    printf("[OK] Verification successful! The output is valid.\n");


    // 7. CLEANUP: Destroy all created objects
    printf("--- Cleaning up ---\n");
    voprf_private_key_destroy(server_sk);
    voprf_public_key_destroy(server_pk);
    voprf_private_key_destroy(blinding_factor);
    voprf_point_destroy(blinded_point);
    voprf_point_destroy(evaluated_point);
    voprf_point_destroy(final_output);
    printf("[OK] All resources freed.\n");

    return 0;
}
Serialization and DeserializationTo store or transmit keys and points, you can serialize them to byte buffers. The API uses a two-step process to ensure memory safety.// Example: Serialize and deserialize a public key
voprf_public_key_t* pk = ...; // assume pk is a valid key

// Step 1: Get the required size
size_t buffer_size = 0;
status = voprf_public_key_get_byte_size(pk, &buffer_size);
check_status(status, "get pk size");

// Step 2: Allocate memory and serialize
uint8_t* buffer = malloc(buffer_size);
assert(buffer != NULL);
status = voprf_public_key_to_bytes(pk, buffer, buffer_size);
check_status(status, "pk to bytes");

// ... transmit or store the buffer ...

// Now deserialize it back
voprf_public_key_t* pk_reconstructed = NULL;
status = voprf_public_key_from_bytes(&pk_reconstructed, buffer, buffer_size);
check_status(status, "pk from bytes");

// Don't forget to clean up
free(buffer);
voprf_public_key_destroy(pk);
voprf_public_key_destroy(pk_reconstructed);
LicenseThis project is licensed under the [YOUR LICENSE HERE] License. See the LICENSE file for details.