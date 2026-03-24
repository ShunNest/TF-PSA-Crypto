/*
 *  PSA Ed25519 helper layer for builtin driver.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_ED25519_H
#define PSA_CRYPTO_ED25519_H

#include "psa/crypto.h"

psa_status_t mbedtls_psa_ed25519_import_key(const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits);

psa_status_t mbedtls_psa_ed25519_export_public_key(const psa_key_attributes_t *attributes,
                                                   const uint8_t *key_buffer, size_t key_buffer_size,
                                                   uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t mbedtls_psa_ed25519_generate_key(const psa_key_attributes_t *attributes,
                                              uint8_t *key_buffer, size_t key_buffer_size,
                                              size_t *key_buffer_length);

psa_status_t mbedtls_psa_ed25519_sign_message(const psa_key_attributes_t *attributes,
                                              const uint8_t *key_buffer, size_t key_buffer_size,
                                              const uint8_t *input, size_t input_length,
                                              uint8_t *signature, size_t signature_size,
                                              size_t *signature_length);

psa_status_t mbedtls_psa_ed25519_verify_message(const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer, size_t key_buffer_size,
                                                const uint8_t *input, size_t input_length,
                                                const uint8_t *signature, size_t signature_length);

#endif /* PSA_CRYPTO_ED25519_H */

