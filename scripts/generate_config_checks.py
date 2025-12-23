#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

from typing import Iterator

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import
from mbedtls_framework import config_macros

ALWAYS_ENABLED_SINCE_1_0 = frozenset([
    'MBEDTLS_PSA_CRYPTO_CONFIG',
    'MBEDTLS_USE_PSA_CRYPTO',
])

def checkers_for_removed_options() -> Iterator[Checker]:
    """Discover removed options. Yield corresponding checkers."""
    previous_major = config_macros.History('mbedtls', '3.6')
    this_major = config_macros.History('tfpsacrypto', '1.0')
    tls = config_macros.History('mbedtls', '4.0')
    new_public = this_major.options() | tls.options()
    old_public = previous_major.options()
    internal = this_major.internal()
    for option in sorted(old_public - new_public):
        if option in ALWAYS_ENABLED_SINCE_1_0:
            continue
        if option in internal:
            yield Internal(option)
        else:
            yield Removed(option, 'TF-PSA_Crypto 1.0')

def all_checkers() -> Iterator[Checker]:
    """Yield all checkers."""
    yield from checkers_for_removed_options()

CRYPTO_CHECKS = BranchData(
    header_directory='core',
    header_prefix='tf_psa_crypto_',
    project_cpp_prefix='TF_PSA_CRYPTO',
    checkers=list(all_checkers()),
)

if __name__ == '__main__':
    main(CRYPTO_CHECKS)
