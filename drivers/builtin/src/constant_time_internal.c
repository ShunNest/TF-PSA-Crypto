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

#include "tf_psa_crypto_common.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/private/error_common.h"
#include "mbedtls/platform_util.h"

#include <stdint.h>

#if !defined(MBEDTLS_CT_ASM)
/*
 * Define an object with the value zero, such that the compiler cannot prove that it
 * has the value zero (because it is volatile, it "may be modified in ways unknown to
 * the implementation").
 */
volatile mbedtls_ct_uint_t mbedtls_ct_zero = 0;
#endif

#if defined(MBEDTLS_NIST_KW_C)

int mbedtls_ct_memcmp_partial(const void *a,
                              const void *b,
                              size_t n,
                              size_t skip_head,
                              size_t skip_tail)
{
    unsigned int diff = 0;

    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;

    size_t valid_end = n - skip_tail;

    for (size_t i = 0; i < n; i++) {
        unsigned char x = A[i], y = B[i];
        unsigned int d = x ^ y;
        mbedtls_ct_condition_t valid = mbedtls_ct_bool_and(mbedtls_ct_uint_ge(i, skip_head),
                                                           mbedtls_ct_uint_lt(i, valid_end));
        diff |= mbedtls_ct_uint_if_else_0(valid, d);
    }

    /* Since we go byte-by-byte, the only bits set will be in the bottom 8 bits, so the
     * cast from uint to int is safe. */
    return (int) diff;
}

#endif

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)

void mbedtls_ct_memmove_left(void *start, size_t total, size_t offset)
{
    volatile unsigned char *buf = start;
    for (size_t i = 0; i < total; i++) {
        mbedtls_ct_condition_t no_op = mbedtls_ct_uint_gt(total - offset, i);
        /* The first `total - offset` passes are a no-op. The last
         * `offset` passes shift the data one byte to the left and
         * zero out the last byte. */
        for (size_t n = 0; n < total - 1; n++) {
            unsigned char current = buf[n];
            unsigned char next    = buf[n+1];
            buf[n] = mbedtls_ct_uint_if(no_op, current, next);
        }
        buf[total-1] = mbedtls_ct_uint_if_else_0(no_op, buf[total-1]);
    }
}

#endif /* MBEDTLS_PKCS1_V15 && MBEDTLS_RSA_C */

void mbedtls_ct_memcpy_if(mbedtls_ct_condition_t condition,
                          unsigned char *dest,
                          const unsigned char *src1,
                          const unsigned char *src2,
                          size_t len)
{
#if defined(MBEDTLS_CT_SIZE_64)
    const uint64_t mask     = (uint64_t) condition;
    const uint64_t not_mask = (uint64_t) ~mbedtls_ct_compiler_opaque(condition);
#else
    const uint32_t mask     = (uint32_t) condition;
    const uint32_t not_mask = (uint32_t) ~mbedtls_ct_compiler_opaque(condition);
#endif

    /* If src2 is NULL, setup src2 so that we read from the destination address.
     *
     * This means that if src2 == NULL && condition is false, the result will be a
     * no-op because we read from dest and write the same data back into dest.
     */
    if (src2 == NULL) {
        src2 = dest;
    }

    /* dest[i] = c1 == c2 ? src[i] : dest[i] */
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
#if defined(MBEDTLS_CT_SIZE_64)
    for (; (i + 8) <= len; i += 8) {
        uint64_t a = mbedtls_get_unaligned_uint64(src1 + i) & mask;
        uint64_t b = mbedtls_get_unaligned_uint64(src2 + i) & not_mask;
        mbedtls_put_unaligned_uint64(dest + i, a | b);
    }
#else
    for (; (i + 4) <= len; i += 4) {
        uint32_t a = mbedtls_get_unaligned_uint32(src1 + i) & mask;
        uint32_t b = mbedtls_get_unaligned_uint32(src2 + i) & not_mask;
        mbedtls_put_unaligned_uint32(dest + i, a | b);
    }
#endif /* defined(MBEDTLS_CT_SIZE_64) */
#endif /* MBEDTLS_EFFICIENT_UNALIGNED_ACCESS */
    for (; i < len; i++) {
        dest[i] = (src1[i] & mask) | (src2[i] & not_mask);
    }
}

void mbedtls_ct_memcpy_offset(unsigned char *dest,
                              const unsigned char *src,
                              size_t offset,
                              size_t offset_min,
                              size_t offset_max,
                              size_t len)
{
    size_t offsetval;

    for (offsetval = offset_min; offsetval <= offset_max; offsetval++) {
        mbedtls_ct_memcpy_if(mbedtls_ct_uint_eq(offsetval, offset), dest, src + offsetval, NULL,
                             len);
    }
}

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)

void mbedtls_ct_zeroize_if(mbedtls_ct_condition_t condition, void *buf, size_t len)
{
    uint32_t mask = (uint32_t) ~condition;
    uint8_t *p = (uint8_t *) buf;
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
    for (; (i + 4) <= len; i += 4) {
        mbedtls_put_unaligned_uint32((void *) (p + i),
                                     mbedtls_get_unaligned_uint32((void *) (p + i)) & mask);
    }
#endif
    for (; i < len; i++) {
        p[i] = p[i] & mask;
    }
}

#endif /* defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) */
