/** \brief Simple integration of mldsa-native from PQCP
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_WRAP_MLDSA_NATIVE_H
#define TF_PSA_CRYPTO_WRAP_MLDSA_NATIVE_H

#include <tf-psa-crypto/build_info.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

/* The mldsa-native config file defines options that apply to all
 * parameter sets. It is included both when building code that uses
 * mldsa-native (via wrap_mldsa_native.h) and when building mldsa-native
 * itself (via wrap_mldsa_native.c). */
#define MLD_CONFIG_FILE "tf-psa-crypto/private/pqcp-config.h"

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED)
#  define MLD_CONFIG_PARAMETER_SET 87
#  include "mldsa_native.h"
#  undef MLD_CONFIG_API_PARAMETER_SET
#endif

#endif  /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* <wrap_mldsa_native.h> */
