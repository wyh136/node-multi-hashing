#ifndef SHA2_H
#define SHA2_H
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>

void sha256_init(uint32_t *state);
extern "C" void sha256_transform(uint32_t *state, const uint32_t *block, int swap);
void sha256d(unsigned char *hash, const unsigned char *data, int len);

#if defined(__ARM_NEON__) || defined(__ALTIVEC__) || defined(__i386__) || defined(__x86_64__)
#define HAVE_SHA256_4WAY 1
extern "C" int sha256_use_4way();
extern "C" void sha256_init_4way(uint32_t *state);
extern "C" void sha256_transform_4way(uint32_t *state, const uint32_t *block, int swap);
#endif

#if defined(__x86_64__) && defined(USE_AVX2)
#define HAVE_SHA256_8WAY 1
extern "C" int sha256_use_8way();
extern "C" void sha256_init_8way(uint32_t *state);
extern "C" void sha256_transform_8way(uint32_t *state, const uint32_t *block, int swap);
#endif
#endif
