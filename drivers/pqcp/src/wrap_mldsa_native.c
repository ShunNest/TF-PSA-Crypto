/** \brief Simple integration of mldsa-native from PQCP
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <tf-psa-crypto/build_info.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#include <tf-psa-crypto/private/pqcp-config.h>

/* If we include multiple levels, tell the first level to include the
 * shared stuff.
 * After including the first level, we'll tell the other levels not to
 * include the shared stuff.
 */
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED)
#  define MLD_CONFIG_PARAMETER_SET 87
#  include "mldsa_native.c"
#  undef MLD_CONFIG_PARAMETER_SET
#  undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#  define MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */
