#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>

static const int SCRYPT_SCRATCHPAD_SIZE = 134217791;
static const int N = 1048576;

void scryptSquaredHash(const uint32_t *input, uint32_t *output);
extern unsigned char *scrypt_buffer_alloc();
extern "C" void scrypt_core(uint32_t *X, uint32_t *V, int N);
int scrypt_best_throughput();

#if defined(__x86_64__)
//#define SCRYPT_MAX_WAYS 12
//#define HAVE_SCRYPT_3WAY 1
//#define scrypt_best_throughput() 3;
extern "C" void scrypt_core_3way(uint32_t *X, uint32_t *V, int N);

#if defined(USE_AVX2)
#undef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 24
#define HAVE_SCRYPT_6WAY 1
extern "C" void scrypt_core_6way(uint32_t *X, uint32_t *V, int N);
#endif

#elif defined(__i386__)
#define SCRYPT_MAX_WAYS 1
#define scrypt_best_throughput() 1
extern "C" void scrypt_core(uint32_t *X, uint32_t *V, int N);

#elif defined(__arm__) && defined(__APCS_32__)
extern "C" void scrypt_core(uint32_t *X, uint32_t *V, int N);

#if defined(__ARM_NEON__)
#undef HAVE_SHA256_4WAY
#define SCRYPT_MAX_WAYS 1
#define HAVE_SCRYPT_3WAY 0
#define scrypt_best_throughput() 1
#endif
#endif

static inline uint32_t scrypt_le32dec(const void *pp)
{
        const uint8_t *p = (uint8_t const *)pp;
        return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
            ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void scrypt_le32enc(void *pp, uint32_t x)
{
        uint8_t *p = (uint8_t *)pp;
        p[0] = x & 0xff;
        p[1] = (x >> 8) & 0xff;
        p[2] = (x >> 16) & 0xff;
        p[3] = (x >> 24) & 0xff;
}

static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#endif

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
    return __builtin_bswap32(v);
#else
    return bswap_32(v);
#endif
}
#endif
