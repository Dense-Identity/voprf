#include "voprf/voprf.h"

// Include your internal C++ headers for the cryptographic elements.
#include "elements.hpp"

#include <new> // For std::bad_alloc
#include <vector>
#include <string>

//----------------------------------------------------------------
// Internal Error Codes
//----------------------------------------------------------------
enum voprf_error_code {
    VOPRF_SUCCESS = 0,
    VOPRF_ERROR_NULL_ARG = -1,
    VOPRF_ERROR_MALLOC = -2,
    VOPRF_ERROR_SERIALIZATION = -3,
    VOPRF_ERROR_DESERIALIZATION = -4,
    VOPRF_ERROR_INVALID_BUFFER_SIZE = -5,
    VOPRF_ERROR_CPP_EXCEPTION = -10,
};

//----------------------------------------------------------------
// Opaque Struct Definitions
//----------------------------------------------------------------

// These structs wrap the C++ objects. The user of the C API
// only ever sees a pointer to these, never their contents.
struct voprf_private_key_t {
    voprf::SecretKey sk;
};

struct voprf_public_key_t {
    voprf::VerificationKey pk;
};

struct voprf_point_t {
    voprf::Point p;
};


//----------------------------------------------------------------
// Helper Macros
//----------------------------------------------------------------

// Macro to safely handle C++ exceptions at the API boundary.
#define VOPRF_TRY \
    try {

#define VOPRF_CATCH                                        \
    } catch (const std::bad_alloc&) {                      \
        return VOPRF_ERROR_MALLOC;                         \
    } catch (const std::exception&) {                      \
        return VOPRF_ERROR_CPP_EXCEPTION;                  \
    } catch (...) {                                        \
        return VOPRF_ERROR_CPP_EXCEPTION;                  \
    }

// Macro for basic NULL argument checks.
#define CHECK_NULL_ARG(arg) \
    if (!(arg)) { return VOPRF_ERROR_NULL_ARG; }


//----------------------------------------------------------------
// Global Library Initialization
//----------------------------------------------------------------

extern "C" int voprf_init() {
    VOPRF_TRY
        voprf::Init();
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

//----------------------------------------------------------------
// Private Key Management
//----------------------------------------------------------------

extern "C" int voprf_private_key_generate(voprf_private_key_t** key) {
    CHECK_NULL_ARG(key);
    VOPRF_TRY
        voprf_private_key_t* new_key = new voprf_private_key_t();
        new_key->sk = voprf::SecretKey::Keygen();
        *key = new_key;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" void voprf_private_key_destroy(voprf_private_key_t* key) {
    delete key;
}

extern "C" int voprf_private_key_get_public_key(const voprf_private_key_t* private_key, voprf_public_key_t** public_key) {
    CHECK_NULL_ARG(private_key);
    CHECK_NULL_ARG(public_key);
    VOPRF_TRY
        voprf_public_key_t* new_pk = new voprf_public_key_t();
        new_pk->pk = private_key->sk.GetVerificationKey();
        *public_key = new_pk;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_private_key_get_byte_size(const voprf_private_key_t* key, size_t* size) {
    CHECK_NULL_ARG(key);
    CHECK_NULL_ARG(size);
    VOPRF_TRY
        *size = key->sk.ToBytes().size();
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_private_key_to_bytes(const voprf_private_key_t* key, uint8_t* buffer, size_t buffer_len) {
    CHECK_NULL_ARG(key);
    CHECK_NULL_ARG(buffer);
    VOPRF_TRY
        std::vector<uint8_t> bytes = key->sk.ToBytes();
        if (bytes.size() > buffer_len) {
            return VOPRF_ERROR_INVALID_BUFFER_SIZE;
        }
        memcpy(buffer, bytes.data(), bytes.size());
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_private_key_from_bytes(voprf_private_key_t** key, const uint8_t* buffer, size_t buffer_len) {
    CHECK_NULL_ARG(key);
    CHECK_NULL_ARG(buffer);
    VOPRF_TRY
        std::vector<uint8_t> bytes(buffer, buffer + buffer_len);
        voprf_private_key_t* new_key = new voprf_private_key_t();
        new_key->sk = voprf::SecretKey::FromBytes(bytes);
        *key = new_key;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

//----------------------------------------------------------------
// Public Key Management
//----------------------------------------------------------------

extern "C" void voprf_public_key_destroy(voprf_public_key_t* key) {
    delete key;
}

extern "C" int voprf_public_key_get_byte_size(const voprf_public_key_t* key, size_t* size) {
    CHECK_NULL_ARG(key);
    CHECK_NULL_ARG(size);
    VOPRF_TRY
        *size = key->pk.ToBytes().size();
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_public_key_to_bytes(const voprf_public_key_t* key, uint8_t* buffer, size_t buffer_len) {
    CHECK_NULL_ARG(key);
    CHECK_NULL_ARG(buffer);
    VOPRF_TRY
        std::vector<uint8_t> bytes = key->pk.ToBytes();
        if (bytes.size() > buffer_len) {
            return VOPRF_ERROR_INVALID_BUFFER_SIZE;
        }
        memcpy(buffer, bytes.data(), bytes.size());
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_public_key_from_bytes(voprf_public_key_t** key, const uint8_t* buffer, size_t buffer_len) {
    CHECK_NULL_ARG(key);
    CHECK_NULL_ARG(buffer);
    VOPRF_TRY
        std::vector<uint8_t> bytes(buffer, buffer + buffer_len);
        voprf_public_key_t* new_key = new voprf_public_key_t();
        new_key->pk = voprf::VerificationKey::FromBytes(bytes);
        *key = new_key;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

//----------------------------------------------------------------
// Point Management
//----------------------------------------------------------------

extern "C" void voprf_point_destroy(voprf_point_t* point) {
    delete point;
}

extern "C" int voprf_point_get_byte_size(const voprf_point_t* point, size_t* size) {
    CHECK_NULL_ARG(point);
    CHECK_NULL_ARG(size);
    VOPRF_TRY
        *size = point->p.ToBytes().size();
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_point_to_bytes(const voprf_point_t* point, uint8_t* buffer, size_t buffer_len) {
    CHECK_NULL_ARG(point);
    CHECK_NULL_ARG(buffer);
    VOPRF_TRY
        std::vector<uint8_t> bytes = point->p.ToBytes();
        if (bytes.size() > buffer_len) {
            return VOPRF_ERROR_INVALID_BUFFER_SIZE;
        }
        memcpy(buffer, bytes.data(), bytes.size());
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_point_from_bytes(voprf_point_t** point, const uint8_t* buffer, size_t buffer_len) {
    CHECK_NULL_ARG(point);
    CHECK_NULL_ARG(buffer);
    VOPRF_TRY
        std::vector<uint8_t> bytes(buffer, buffer + buffer_len);
        voprf_point_t* new_point = new voprf_point_t();
        new_point->p = voprf::Point::FromBytes(bytes);
        *point = new_point;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_point_equal(const voprf_point_t* p1, const voprf_point_t* p2, bool* equal) {
    CHECK_NULL_ARG(p1);
    CHECK_NULL_ARG(p2);
    CHECK_NULL_ARG(equal);
    VOPRF_TRY
        *equal = (p1->p == p2->p);
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

//----------------------------------------------------------------
// Core VOPRF Operations
//----------------------------------------------------------------

extern "C" int voprf_blind(const uint8_t* msg, size_t msg_len, voprf_private_key_t** blinding_factor, voprf_point_t** blinded_point) {
    CHECK_NULL_ARG(msg);
    CHECK_NULL_ARG(blinding_factor);
    CHECK_NULL_ARG(blinded_point);
    VOPRF_TRY
        std::string msg_str(reinterpret_cast<const char*>(msg), msg_len);
        
        // Logic from VOPRF::Blind
        voprf::SecretKey r = voprf::SecretKey::Keygen();
        voprf::Point x = voprf::Point::Mul(voprf::Point::HashToPoint(msg_str), r);

        voprf_private_key_t* r_out = new voprf_private_key_t{r};
        voprf_point_t* x_out = new voprf_point_t{x};

        *blinding_factor = r_out;
        *blinded_point = x_out;

        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_evaluate(const voprf_private_key_t* sk, const voprf_point_t* blinded_point, voprf_point_t** evaluated_point) {
    CHECK_NULL_ARG(sk);
    CHECK_NULL_ARG(blinded_point);
    CHECK_NULL_ARG(evaluated_point);
    VOPRF_TRY
        // Logic from VOPRF::Evaluate
        voprf::Point result = voprf::Point::Mul(blinded_point->p, sk->sk);

        voprf_point_t* new_point = new voprf_point_t{result};
        *evaluated_point = new_point;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_unblind(const voprf_point_t* evaluated_point, const voprf_private_key_t* blinding_factor, voprf_point_t** final_output) {
    CHECK_NULL_ARG(evaluated_point);
    CHECK_NULL_ARG(blinding_factor);
    CHECK_NULL_ARG(final_output);
    VOPRF_TRY
        // Logic from VOPRF::Unblind
        voprf::SecretKey r_inv = blinding_factor->sk.Inverse();
        voprf::Point result = voprf::Point::Mul(evaluated_point->p, r_inv);
        
        voprf_point_t* new_point = new voprf_point_t{result};
        *final_output = new_point;
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}

extern "C" int voprf_verify(const voprf_public_key_t* pk, const uint8_t* input_msg, size_t input_msg_len, const voprf_point_t* output_point, bool* result) {
    CHECK_NULL_ARG(pk);
    CHECK_NULL_ARG(input_msg);
    CHECK_NULL_ARG(output_point);
    CHECK_NULL_ARG(result);
    VOPRF_TRY
        std::string msg_str(reinterpret_cast<const char*>(input_msg), input_msg_len);

        // Logic from VOPRF::Verify
        voprf::Pairing e1 = voprf::Pairing::Pair(voprf::Point::HashToPoint(msg_str), pk->pk);
        voprf::Pairing e2 = voprf::Pairing::Pair(output_point->p, voprf::VerificationKey::GetBase());
        
        *result = (e1 == e2);
        return VOPRF_SUCCESS;
    VOPRF_CATCH
}
