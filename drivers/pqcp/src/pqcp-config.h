/**
 * \file tf-psa-crypto/private/pqcp-config.h
 *
 * \brief Define the mldsa-native configuration from the TF-PSA-Crypto
 *        configuration.
 *
 * This file defines configuration macros of mldsa-native that are
 * independent of the parameter set.
 * It can be set as `MLD_CONFIG_FILE` when building mldsa-native,
 * and can be included before `mldsa_native.c`.
 *
 * In addition, you need to define parameter-set-specific macros:
 * - `MLD_CONFIG_PARAMETER_SET` and `MLD_CONFIG_NAMESPACE_PREFIX` when
 *   building mldsa-native, which needs to be done once per supported
 *   parameter set.
 * - `MLD_CONFIG_API_PARAMETER_SET` and `MLD_CONFIG_API_NAMESPACE_PREFIX`
 *   before including `mldsa_native.h`, which needs to be done once per
 *   supported parameter set.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_PQCP_CONFIG_H
#define TF_PSA_CRYPTO_PRIVATE_PQCP_CONFIG_H

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#include <mbedtls/platform_util.h>

/* Use our own zeroize function */
#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize mbedtls_platform_zeroize

/* Don't expose internal functions to the linker. This lets the compiler
 * optimize more. */
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static

/* Set up mldsa-native for supporting multiple parameter sets.
 * This only affects function names and the ability to share some
 * parameter-set-independent functions. It's ok to use this even if we
 * only activate one parameter set.
 */
#define MLD_CONFIG_MULTILEVEL_BUILD

/* Prefix for exported function names */
#define MLD_CONFIG_NAMESPACE_PREFIX tf_psa_crypto_pqcp_mldsa

/* We have not integrated our RNG into mldsa-native. Instead, we call
 * lower-level deterministic functions directly, and take care of the RNG
 * calls ourselves. */
#define MLD_CONFIG_NO_RANDOMIZED_API

/* Disable SUPERCOP interface. We don't care about that. */
#define MLD_CONFIG_NO_SUPERCOP

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif  /* tf-psa-crypto/private/pqcp-config.h */
