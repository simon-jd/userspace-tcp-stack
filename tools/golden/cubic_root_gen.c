// SPDX-License-Identifier: GPL-2.0-only
// Reference function from Linux v7.0 net/ipv4/tcp_cubic.c (Stephen Hemminger,
// original BIC implementation by Injong Rhee and Lisong Xu).
// cc -std=c11 cubic_root_gen.c -o cubic-root-gen && ./cubic-root-gen
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
static u32 fls64(u64 a) { return a ? 64u - (u32)__builtin_clzll(a) : 0; }
static u64 div64_u64(u64 a, u64 b) { return a / b; }

static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

int main(void)
{
    for (u32 i = 0; i < 64; ++i)
        printf("%u,%c", cubic_root(i), i % 16 == 15 ? '\n' : ' ');
    for (u32 i = 8; i < 64; ++i)
        printf("%u,%c", cubic_root((u64)i << 9), i % 8 == 7 ? '\n' : ' ');
    for (u32 b = 6; b < 64; ++b) {
        u64 n = UINT64_C(1) << b;
        printf("{%u, %u, %u},\n", cubic_root(n-1), cubic_root(n), cubic_root(n+1));
    }
    printf("max=%u K=%u\n", cubic_root(UINT64_MAX), cubic_root(UINT64_C(80452070310)));
    return 0;
}
