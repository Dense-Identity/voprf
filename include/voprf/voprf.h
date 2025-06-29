#ifndef VOPRF_H
#define VOPRF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

//----------------------------------------------------------------
// Opaque Type Definitions
//----------------------------------------------------------------

/** @brief An opaque pointer to a private key object. */
typedef struct voprf_private_key_t voprf_private_key_t;

/** @brief An opaque pointer to a public key object. */
typedef struct voprf_public_key_t voprf_public_key_t;

/** @brief An opaque pointer to an elliptic curve point object. */
typedef struct voprf_point_t voprf_point_t;

//----------------------------------------------------------------
// Global Library Initialization
//----------------------------------------------------------------

/**
 * @brief Initializes the underlying cryptographic library.
 *
 * This function must be called once before any other function in this library.
 * It sets up the necessary global state for the pairing-based cryptography.
 *
 * @return 0 on success, non-zero on failure.
 */
int voprf_init();

//----------------------------------------------------------------
// Private Key Management
//----------------------------------------------------------------

/**
 * @brief Generates a new, random private key.
 *
 * @param[out] key A pointer to receive the newly created private key object.
 * @return 0 on success, non-zero on failure.
 */
int voprf_private_key_generate(voprf_private_key_t** key);

/**
 * @brief Destroys a private key object and frees its memory.
 *
 * @param key The private key object to destroy. Can be NULL.
 */
void voprf_private_key_destroy(voprf_private_key_t* key);

/**
 * @brief Derives the corresponding public key from a private key.
 *
 * @param[in] private_key The private key.
 * @param[out] public_key A pointer to receive the derived public key object.
 * @return 0 on success, non-zero on failure.
 */
int voprf_private_key_get_public_key(const voprf_private_key_t* private_key, voprf_public_key_t** public_key);

/**
 * @brief Gets the required buffer size for serializing a private key.
 *
 * @param[in] key The private key object.
 * @param[out] size A pointer to store the required size in bytes.
 * @return 0 on success, non-zero on failure.
 */
int voprf_private_key_get_byte_size(const voprf_private_key_t* key, size_t* size);

/**
 * @brief Serializes a private key into a byte buffer.
 *
 * The caller must ensure the buffer is at least the size returned by
 * `voprf_private_key_get_byte_size`.
 *
 * @param[in] key The private key object.
 * @param[out] buffer The buffer to write the serialized key into.
 * @param[in] buffer_len The size of the output buffer.
 * @return 0 on success, non-zero on failure.
 */
int voprf_private_key_to_bytes(const voprf_private_key_t* key, uint8_t* buffer, size_t buffer_len);

/**
 * @brief Deserializes a private key from a byte buffer.
 *
 * @param[out] key A pointer to receive the newly created private key object.
 * @param[in] buffer The buffer containing the serialized key.
 * @param[in] buffer_len The size of the input buffer.
 * @return 0 on success, non-zero on failure.
 */
int voprf_private_key_from_bytes(voprf_private_key_t** key, const uint8_t* buffer, size_t buffer_len);


//----------------------------------------------------------------
// Public Key Management
//----------------------------------------------------------------

/**
 * @brief Destroys a public key object and frees its memory.
 *
 * @param key The public key object to destroy. Can be NULL.
 */
void voprf_public_key_destroy(voprf_public_key_t* key);

/**
 * @brief Gets the required buffer size for serializing a public key.
 *
 * @param[in] key The public key object.
 * @param[out] size A pointer to store the required size in bytes.
 * @return 0 on success, non-zero on failure.
 */
int voprf_public_key_get_byte_size(const voprf_public_key_t* key, size_t* size);

/**
 * @brief Serializes a public key into a byte buffer.
 *
 * @param[in] key The public key object.
 * @param[out] buffer The buffer to write the serialized key into.
 * @param[in] buffer_len The size of the output buffer.
 * @return 0 on success, non-zero on failure.
 */
int voprf_public_key_to_bytes(const voprf_public_key_t* key, uint8_t* buffer, size_t buffer_len);

/**
 * @brief Deserializes a public key from a byte buffer.
 *
 * @param[out] key A pointer to receive the newly created public key object.
 * @param[in] buffer The buffer containing the serialized key.
 * @param[in] buffer_len The size of the input buffer.
 * @return 0 on success, non-zero on failure.
 */
int voprf_public_key_from_bytes(voprf_public_key_t** key, const uint8_t* buffer, size_t buffer_len);


//----------------------------------------------------------------
// Point Management
//----------------------------------------------------------------

/**
 * @brief Destroys a point object and frees its memory.
 *
 * @param point The point object to destroy. Can be NULL.
 */
void voprf_point_destroy(voprf_point_t* point);

/**
 * @brief Gets the required buffer size for serializing a point.
 *
 * @param[in] point The point object.
 * @param[out] size A pointer to store the required size in bytes.
 * @return 0 on success, non-zero on failure.
 */
int voprf_point_get_byte_size(const voprf_point_t* point, size_t* size);

/**
 * @brief Serializes a point into a byte buffer.
 *
 * @param[in] point The point object.
 * @param[out] buffer The buffer to write the serialized point into.
 * @param[in] buffer_len The size of the output buffer.
 * @return 0 on success, non-zero on failure.
 */
int voprf_point_to_bytes(const voprf_point_t* point, uint8_t* buffer, size_t buffer_len);

/**
 * @brief Deserializes a point from a byte buffer.
 *
 * @param[out] point A pointer to receive the newly created point object.
 * @param[in] buffer The buffer containing the serialized point.
 * @param[in] buffer_len The size of the input buffer.
 * @return 0 on success, non-zero on failure.
 */
int voprf_point_from_bytes(voprf_point_t** point, const uint8_t* buffer, size_t buffer_len);

/**
 * @brief Checks if two point objects are equal.
 *
 * @param[in] p1 The first point.
 * @param[in] p2 The second point.
 * @param[out] equal A pointer to store the boolean result (true if equal, false otherwise).
 * @return 0 on success, non-zero on failure.
 */
int voprf_point_equal(const voprf_point_t* p1, const voprf_point_t* p2, bool* equal);

//----------------------------------------------------------------
// Core VOPRF Operations
//----------------------------------------------------------------

/**
 * @brief Hashes an input message and blinds it.
 *
 * This is the first step for a client in the OPRF protocol.
 *
 * @param[in] msg The input message buffer.
 * @param[in] msg_len The length of the input message.
 * @param[out] blinding_factor A pointer to receive the random blinding factor (a private key).
 * @param[out] blinded_point A pointer to receive the resulting blinded point.
 * @return 0 on success, non-zero on failure.
 */
int voprf_blind(const uint8_t* msg, size_t msg_len, voprf_private_key_t** blinding_factor, voprf_point_t** blinded_point);

/**
 * @brief Evaluates the OPRF function on a blinded point.
 *
 * This is the server-side step of the OPRF protocol.
 *
 * @param[in] sk The server's private key.
 * @param[in] blinded_point The blinded point received from the client.
 * @param[out] evaluated_point A pointer to receive the resulting evaluated point.
 * @return 0 on success, non-zero on failure.
 */
int voprf_evaluate(const voprf_private_key_t* sk, const voprf_point_t* blinded_point, voprf_point_t** evaluated_point);

/**
 * @brief Unblinds an evaluated point to get the final OPRF output.
 *
 * This is the second step for a client, after receiving the evaluated point from the server.
 *
 * @param[in] evaluated_point The point received from the server.
 * @param[in] blinding_factor The random blinding factor generated in the `voprf_blind` step.
 * @param[out] final_output A pointer to receive the final, unblinded OPRF output point.
 * @return 0 on success, non-zero on failure.
 */
int voprf_unblind(const voprf_point_t* evaluated_point, const voprf_private_key_t* blinding_factor, voprf_point_t** final_output);

/**
 * @brief Verifies that an OPRF output corresponds to a given input and public key.
 *
 * @param[in] pk The server's public key.
 * @param[in] input_msg The original input message.
 * @param[in] input_msg_len The length of the input message.
 * @param[in] output_point The final OPRF output point to verify.
 * @param[out] result A pointer to store the boolean verification result.
 * @return 0 on success, non-zero on failure.
 */
int voprf_verify(const voprf_public_key_t* pk, const uint8_t* input_msg, size_t input_msg_len, const voprf_point_t* output_point, bool* result);


#ifdef __cplusplus
}
#endif

#endif // VOPRF_H
