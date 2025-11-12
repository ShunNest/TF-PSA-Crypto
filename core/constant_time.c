/**
 *  Constant-time functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * The following functions are implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */

#include <stdint.h>
#include <limits.h>

#include "tf_psa_crypto_common.h"
#include "mbedtls/constant_time.h"

/*
 * Define MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS where assembly is present to
 * perform fast unaligned access to volatile data.
 *
 * This is needed because mbedtls_get_unaligned_uintXX etc don't support volatile
 * memory accesses.
 *
 * Some of these definitions could be moved into alignment.h but for now they are
 * only used here.
 */
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS) && \
    ((defined(MBEDTLS_CT_ARM_ASM) && (UINTPTR_MAX == 0xfffffffful)) || \
    defined(MBEDTLS_CT_AARCH64_ASM))
/* We check pointer sizes to avoid issues with them not matching register size requirements */
#define MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS

static inline uint32_t mbedtls_get_unaligned_volatile_uint32(volatile const unsigned char *p)
{
    /* This is UB, even where it's safe:
     *    return *((volatile uint32_t*)p);
     * so instead the same thing is expressed in assembly below.
     */
    uint32_t r;
#if defined(MBEDTLS_CT_ARM_ASM)
    asm volatile ("ldr %0, [%1]" : "=r" (r) : "r" (p) :);
#elif defined(MBEDTLS_CT_AARCH64_ASM)
    asm volatile ("ldr %w0, [%1]" : "=r" (r) : MBEDTLS_ASM_AARCH64_PTR_CONSTRAINT(p) :);
#else
#error "No assembly defined for mbedtls_get_unaligned_volatile_uint32"
#endif
    return r;
}
#endif /* defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS) &&
          (defined(MBEDTLS_CT_ARM_ASM) || defined(MBEDTLS_CT_AARCH64_ASM)) */

int mbedtls_ct_memcmp(const void *a,
                      const void *b,
                      size_t n)
{
    size_t i = 0;
    /*
     * `A` and `B` are cast to volatile to ensure that the compiler
     * generates code that always fully reads both buffers.
     * Otherwise it could generate a test to exit early if `diff` has all
     * bits set early in the loop.
     */
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    uint32_t diff = 0;

#if defined(MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS)
    for (; (i + 4) <= n; i += 4) {
        uint32_t x = mbedtls_get_unaligned_volatile_uint32(A + i);
        uint32_t y = mbedtls_get_unaligned_volatile_uint32(B + i);
        diff |= x ^ y;
    }
#endif

    for (; i < n; i++) {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }


#if (INT_MAX < INT32_MAX)
    /* We don't support int smaller than 32-bits, but if someone tried to build
     * with this configuration, there is a risk that, for differing data, the
     * only bits set in diff are in the top 16-bits, and would be lost by a
     * simple cast from uint32 to int.
     * This would have significant security implications, so protect against it. */
#error "mbedtls_ct_memcmp() requires minimum 32-bit ints"
#else
    /* The bit-twiddling ensures that when we cast uint32_t to int, we are casting
     * a value that is in the range 0..INT_MAX - a value larger than this would
     * result in implementation defined behaviour.
     *
     * This ensures that the value returned by the function is non-zero iff
     * diff is non-zero.
     */
    return (int) ((diff & 0xffff) | (diff >> 16));
#endif
}
