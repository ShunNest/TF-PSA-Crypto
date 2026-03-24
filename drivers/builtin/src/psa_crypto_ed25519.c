/*
 *  PSA Ed25519 helper layer for builtin driver.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa_crypto_ed25519.h"

#include "psa_util_internal.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

/* TweetNaCl reference implementation (public domain): https://tweetnacl.cr.yp.to/ */
#include "thirdparty/tweetnacl.h"

#define MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE 32u
#define MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE 32u
#define MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE 64u
#define MBEDTLS_PSA_ED25519_SIGNATURE_SIZE 64u

void randombytes(unsigned char *out, unsigned long long out_len);

void randombytes(unsigned char *out, unsigned long long out_len)
{
    if (out == NULL) {
        return;
    }

    while (out_len > 0u) {
        size_t chunk = (out_len > (unsigned long long) SIZE_MAX) ? SIZE_MAX : (size_t) out_len;
        if (mbedtls_psa_get_random(NULL, out, chunk) != 0) {
            mbedtls_platform_zeroize(out, chunk);
            return;
        }
        out += chunk;
        out_len -= (unsigned long long) chunk;
    }
}

static int psa_ed25519_attributes_valid(const psa_key_attributes_t *attributes)
{
    psa_key_type_t type;
    psa_key_type_t family;
    size_t bits;

    if (attributes == NULL) {
        return 0;
    }

    type = psa_get_key_type(attributes);
    family = PSA_KEY_TYPE_ECC_GET_FAMILY(type);
    bits = psa_get_key_bits(attributes);

    if (!PSA_KEY_TYPE_IS_ECC(type)) {
        return 0;
    }
    if (family != PSA_ECC_FAMILY_TWISTED_EDWARDS) {
        return 0;
    }
    if (!(bits == 255u || bits == 256u)) {
        return 0;
    }
    return 1;
}

static psa_status_t psa_ed25519_expand_private_key(const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t out_private[MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE])
{
    if (key_buffer == NULL || out_private == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_buffer_size == MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE) {
        memcpy(out_private, key_buffer, MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE);
        return PSA_SUCCESS;
    }

    if (key_buffer_size == MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) {
        uint8_t pub[MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE];
        if (crypto_sign_seed_keypair(pub, out_private, key_buffer) != 0) {
            mbedtls_platform_zeroize(pub, sizeof(pub));
            mbedtls_platform_zeroize(out_private, MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE);
            return PSA_ERROR_HARDWARE_FAILURE;
        }
        mbedtls_platform_zeroize(pub, sizeof(pub));
        return PSA_SUCCESS;
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_status_t psa_ed25519_public_from_private_key(const uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        uint8_t out_public[MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE])
{
    if (key_buffer == NULL || out_public == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_buffer_size == MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE) {
        memcpy(out_public, key_buffer + MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE, MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE);
        return PSA_SUCCESS;
    }

    if (key_buffer_size == MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) {
        uint8_t expanded[MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE];
        if (crypto_sign_seed_keypair(out_public, expanded, key_buffer) != 0) {
            mbedtls_platform_zeroize(expanded, sizeof(expanded));
            mbedtls_platform_zeroize(out_public, MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE);
            return PSA_ERROR_HARDWARE_FAILURE;
        }
        mbedtls_platform_zeroize(expanded, sizeof(expanded));
        return PSA_SUCCESS;
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t mbedtls_psa_ed25519_import_key(const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits)
{
    psa_key_type_t type;

    if (!psa_ed25519_attributes_valid(attributes) ||
        data == NULL || data_length == 0u ||
        key_buffer == NULL || key_buffer_length == NULL || bits == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);

    if (PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        if (data_length == MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) {
            if (key_buffer_size < MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(key_buffer, data, MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE);
            *key_buffer_length = MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE;
        } else if (data_length == MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE) {
            uint8_t expected_public[MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE];
            uint8_t expanded[MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE];
            psa_status_t status = PSA_SUCCESS;
            if (key_buffer_size < MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            if (crypto_sign_seed_keypair(expected_public, expanded, data) != 0) {
                status = PSA_ERROR_HARDWARE_FAILURE;
            } else if (memcmp(expected_public,
                              data + MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE,
                              MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE) != 0) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            mbedtls_platform_zeroize(expected_public, sizeof(expected_public));
            mbedtls_platform_zeroize(expanded, sizeof(expanded));
            if (status != PSA_SUCCESS) {
                return status;
            }
            memcpy(key_buffer, data, MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE);
            *key_buffer_length = MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE;
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else if (PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        if (data_length != MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE ||
            key_buffer_size < MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        memcpy(key_buffer, data, MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE);
        *key_buffer_length = MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *bits = 255u;
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_ed25519_export_public_key(const psa_key_attributes_t *attributes,
                                                   const uint8_t *key_buffer, size_t key_buffer_size,
                                                   uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_key_type_t type;
    const uint8_t *pub = NULL;

    if (!psa_ed25519_attributes_valid(attributes) ||
        key_buffer == NULL || data == NULL || data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_size < MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    type = psa_get_key_type(attributes);
    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        if (key_buffer_size != MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        pub = key_buffer;
    } else if (PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        uint8_t derived_public[MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE];
        psa_status_t status = psa_ed25519_public_from_private_key(key_buffer, key_buffer_size, derived_public);
        if (status != PSA_SUCCESS) {
            mbedtls_platform_zeroize(derived_public, sizeof(derived_public));
            return status;
        }
        memcpy(data, derived_public, MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE);
        *data_length = MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE;
        mbedtls_platform_zeroize(derived_public, sizeof(derived_public));
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    memcpy(data, pub, MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE);
    *data_length = MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE;
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_ed25519_generate_key(const psa_key_attributes_t *attributes,
                                              uint8_t *key_buffer, size_t key_buffer_size,
                                              size_t *key_buffer_length)
{
    uint8_t *priv;

    if (!psa_ed25519_attributes_valid(attributes) ||
        key_buffer == NULL || key_buffer_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_KEY_TYPE_IS_KEY_PAIR(psa_get_key_type(attributes))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_buffer_size < MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    priv = key_buffer;
    if (mbedtls_psa_get_random(NULL, priv, MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE) != 0) {
        mbedtls_platform_zeroize(key_buffer, key_buffer_size);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *key_buffer_length = MBEDTLS_PSA_ED25519_PRIVATE_KEY_SEED_SIZE;
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_ed25519_sign_message(const psa_key_attributes_t *attributes,
                                              const uint8_t *key_buffer, size_t key_buffer_size,
                                              const uint8_t *input, size_t input_length,
                                              uint8_t *signature, size_t signature_size,
                                              size_t *signature_length)
{
    unsigned char *signed_message = NULL;
    unsigned long long signed_len = 0u;
    size_t alloc_size;
    uint8_t expanded_private[MBEDTLS_PSA_ED25519_PRIVATE_KEY_EXT_SIZE];
    psa_status_t expand_status;

    if (!psa_ed25519_attributes_valid(attributes) ||
        key_buffer == NULL || input == NULL ||
        signature == NULL || signature_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_KEY_TYPE_IS_KEY_PAIR(psa_get_key_type(attributes))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (signature_size < MBEDTLS_PSA_ED25519_SIGNATURE_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (input_length > (SIZE_MAX - MBEDTLS_PSA_ED25519_SIGNATURE_SIZE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    alloc_size = input_length + MBEDTLS_PSA_ED25519_SIGNATURE_SIZE;

    signed_message = mbedtls_calloc(1, alloc_size);
    if (signed_message == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    expand_status = psa_ed25519_expand_private_key(key_buffer, key_buffer_size, expanded_private);
    if (expand_status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(signed_message, alloc_size);
        mbedtls_free(signed_message);
        return expand_status;
    }

    if (crypto_sign(signed_message, &signed_len, input, (unsigned long long) input_length, expanded_private) != 0 ||
        signed_len != (unsigned long long) alloc_size) {
        mbedtls_platform_zeroize(expanded_private, sizeof(expanded_private));
        mbedtls_platform_zeroize(signed_message, alloc_size);
        mbedtls_free(signed_message);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    mbedtls_platform_zeroize(expanded_private, sizeof(expanded_private));
    memcpy(signature, signed_message, MBEDTLS_PSA_ED25519_SIGNATURE_SIZE);
    *signature_length = MBEDTLS_PSA_ED25519_SIGNATURE_SIZE;
    mbedtls_platform_zeroize(signed_message, alloc_size);
    mbedtls_free(signed_message);
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_ed25519_verify_message(const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer, size_t key_buffer_size,
                                                const uint8_t *input, size_t input_length,
                                                const uint8_t *signature, size_t signature_length)
{
    unsigned char *signed_message = NULL;
    unsigned char *opened_message = NULL;
    unsigned long long opened_len = 0u;
    size_t alloc_size;
    int rc;

    if (!psa_ed25519_attributes_valid(attributes) ||
        key_buffer == NULL || input == NULL || signature == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_buffer_size != MBEDTLS_PSA_ED25519_PUBLIC_KEY_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (signature_length != MBEDTLS_PSA_ED25519_SIGNATURE_SIZE) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (input_length > (SIZE_MAX - MBEDTLS_PSA_ED25519_SIGNATURE_SIZE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    alloc_size = input_length + MBEDTLS_PSA_ED25519_SIGNATURE_SIZE;

    signed_message = mbedtls_calloc(1, alloc_size);
    opened_message = mbedtls_calloc(1, alloc_size);
    if (signed_message == NULL || opened_message == NULL) {
        if (signed_message != NULL) {
            mbedtls_platform_zeroize(signed_message, alloc_size);
            mbedtls_free(signed_message);
        }
        if (opened_message != NULL) {
            mbedtls_platform_zeroize(opened_message, alloc_size);
            mbedtls_free(opened_message);
        }
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    memcpy(signed_message, signature, MBEDTLS_PSA_ED25519_SIGNATURE_SIZE);
    if (input_length != 0u) {
        memcpy(signed_message + MBEDTLS_PSA_ED25519_SIGNATURE_SIZE, input, input_length);
    }

    rc = crypto_sign_open(opened_message, &opened_len, signed_message, (unsigned long long) alloc_size, key_buffer);
    mbedtls_platform_zeroize(signed_message, alloc_size);
    mbedtls_free(signed_message);

    if (rc != 0 || opened_len != (unsigned long long) input_length ||
        (input_length != 0u && memcmp(opened_message, input, input_length) != 0)) {
        mbedtls_platform_zeroize(opened_message, alloc_size);
        mbedtls_free(opened_message);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    mbedtls_platform_zeroize(opened_message, alloc_size);
    mbedtls_free(opened_message);
    return PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
