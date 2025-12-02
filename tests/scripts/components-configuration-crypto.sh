# components-configuration-crypto.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Crypto
################################################################

CMAKE_BUILTIN_BUILD_DIR="drivers/builtin/CMakeFiles/builtin.dir/src"

component_test_accel_ecc_all () {
    msg "build: full + all ECC accelerated"

    # Configure
    # ---------

    ./scripts/config.py full
    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecc.h" ..
    make

    # Make sure built-in EC alg objects are empty.
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    not grep mbedtls_ecjpake_ ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    # Also ensure that ECP module was not re-enabled
    not grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o

    # Run the tests
    # -------------

    msg "test: full + all ECC accelerated"
    ctest
}

component_test_accel_ecc_all_but_ecp_light() {
    msg "build: full + all ECC accelerated but ECP_LIGHT"

    # Configure
    # ---------

    ./scripts/config.py full

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # Emphasize on the configuration that enable ECP_LIGHT. Note that currently
    # ECC key pair derivation acceleration is not supported.
    scripts/config.py set MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py set MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py set PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecc.h" ..
    make

    # Make sure built-in EC alg objects are empty but ECP one.
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o
    not grep mbedtls_ecjpake_ ${CMAKE_BUILTIN_BUILD_DIR}/ecjpake.c.o
    not grep mbedtls_ecp_mul ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o
    grep mbedtls_ecp_ ${CMAKE_BUILTIN_BUILD_DIR}/ecp.c.o

    # Run the tests
    # -------------

    msg "test: full + all ECC accelerated but ECP_LIGHT"
    ctest
}

component_test_accel_ecdh() {
    msg "build: accelerated ECDH"

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecdh.h" ..
    make

    # Make sure built-in ECDH was not re-enabled by accident (additive config)
    not grep mbedtls_psa_key_agreement_ecdh ${CMAKE_BUILTIN_BUILD_DIR}/psa_crypto_ecp.c.o

    # Run the tests
    # -------------

    msg "test: accelerated ECDH"
    ctest
}

component_test_accel_ecdsa() {
    msg "build: accelerated ECDSA"

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR

    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-ecdsa.h" ..
    make

    # Make sure built-in ECDSA was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${CMAKE_BUILTIN_BUILD_DIR}/ecdsa.c.o

    # Run the tests
    # -------------

    msg "test: accelerated ECDSA"
    ctest
}

component_test_accel_hash () {
    msg "test: accelerated hash"

    # Build
    # -----

    cd $OUT_OF_SOURCE_DIR
    cmake -DTF_PSA_CRYPTO_TEST_DRIVER=On \
          -DTF_PSA_CRYPTO_USER_CONFIG_FILE="../tests/configs/user-config-accel-hash.h" ..
    make

    # Make sure built-in hash objects are empty.
    not grep mbedtls_md5 ${CMAKE_BUILTIN_BUILD_DIR}/md5.c.o
    not grep mbedtls_sha1 ${CMAKE_BUILTIN_BUILD_DIR}/sha1.c.o
    not grep mbedtls_sha256 ${CMAKE_BUILTIN_BUILD_DIR}/sha256.c.o
    not grep mbedtls_sha3 ${CMAKE_BUILTIN_BUILD_DIR}/sha3.c.o
    not grep mbedtls_sha512 ${CMAKE_BUILTIN_BUILD_DIR}/sha512.c.o
    not grep mbedtls_ripemd160 ${CMAKE_BUILTIN_BUILD_DIR}/ripemd160.c.o

    # Run the tests
    # -------------

    msg "test: accelerated hash"
    ctest
}
