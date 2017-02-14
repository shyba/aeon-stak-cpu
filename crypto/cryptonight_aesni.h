/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
#pragma once

#include "cryptonight.h"
#include <memory.h>
#include <stdio.h>

#ifdef __GNUC__
#include <x86intrin.h>
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}
#define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#else
#include <intrin.h>
#endif // __GNUC__

#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

extern "C"
{
	void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
	void keccakf(uint64_t st[25], int rounds);
	extern void(*const extra_hashes[4])(const void *, size_t, char *);

	__m128i soft_aesenc(__m128i in, __m128i key);
	__m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
	__m128i tmp4;
	tmp4 = _mm_slli_si128(tmp1, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	return tmp1;
}

template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
	__m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = _mm_aeskeygenassist_si128(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2, uint8_t rcon)
{
	__m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = soft_aeskeygenassist(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = _mm_load_si128(memory);
	xout2 = _mm_load_si128(memory+1);
	*k0 = xout0;
	*k1 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x01);
	else
		aes_genkey_sub<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x02);
	else
		aes_genkey_sub<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x04);
	else
		aes_genkey_sub<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x08);
	else
		aes_genkey_sub<0x08>(&xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}

static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = _mm_aesenc_si128(*x0, key);
	*x1 = _mm_aesenc_si128(*x1, key);
	*x2 = _mm_aesenc_si128(*x2, key);
	*x3 = _mm_aesenc_si128(*x3, key);
	*x4 = _mm_aesenc_si128(*x4, key);
	*x5 = _mm_aesenc_si128(*x5, key);
	*x6 = _mm_aesenc_si128(*x6, key);
	*x7 = _mm_aesenc_si128(*x7, key);
}

static inline void soft_aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = soft_aesenc(*x0, key);
	*x1 = soft_aesenc(*x1, key);
	*x2 = soft_aesenc(*x2, key);
	*x3 = soft_aesenc(*x3, key);
	*x4 = soft_aesenc(*x4, key);
	*x5 = soft_aesenc(*x5, key);
	*x6 = soft_aesenc(*x6, key);
	*x7 = soft_aesenc(*x7, key);
}

template<size_t MEM, bool SOFT_AES, bool PREFETCH>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xin0 = _mm_load_si128(input + 4);
	xin1 = _mm_load_si128(input + 5);
	xin2 = _mm_load_si128(input + 6);
	xin3 = _mm_load_si128(input + 7);
	xin4 = _mm_load_si128(input + 8);
	xin5 = _mm_load_si128(input + 9);
	xin6 = _mm_load_si128(input + 10);
	xin7 = _mm_load_si128(input + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if(SOFT_AES)
		{
			soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}
		else
		{
			aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}

		_mm_store_si128(output + i + 0, xin0);
		_mm_store_si128(output + i + 1, xin1);
		_mm_store_si128(output + i + 2, xin2);
		_mm_store_si128(output + i + 3, xin3);

		if(PREFETCH)
			_mm_prefetch((const char*)output + i + 0, _MM_HINT_T2);

		_mm_store_si128(output + i + 4, xin4);
		_mm_store_si128(output + i + 5, xin5);
		_mm_store_si128(output + i + 6, xin6);
		_mm_store_si128(output + i + 7, xin7);

		if(PREFETCH)
			_mm_prefetch((const char*)output + i + 4, _MM_HINT_T2);
	}
}

template<size_t MEM, bool SOFT_AES, bool PREFETCH>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xout0 = _mm_load_si128(output + 4);
	xout1 = _mm_load_si128(output + 5);
	xout2 = _mm_load_si128(output + 6);
	xout3 = _mm_load_si128(output + 7);
	xout4 = _mm_load_si128(output + 8);
	xout5 = _mm_load_si128(output + 9);
	xout6 = _mm_load_si128(output + 10);
	xout7 = _mm_load_si128(output + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if(PREFETCH)
			_mm_prefetch((const char*)input + i + 0, _MM_HINT_NTA);

		xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
		xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
		xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
		xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

		if(PREFETCH)
			_mm_prefetch((const char*)input + i + 4, _MM_HINT_NTA);

		xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
		xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
		xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
		xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

		if(SOFT_AES)
		{
			soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
		else
		{
			aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
	}

	_mm_store_si128(output + 4, xout0);
	_mm_store_si128(output + 5, xout1);
	_mm_store_si128(output + 6, xout2);
	_mm_store_si128(output + 7, xout3);
	_mm_store_si128(output + 8, xout4);
	_mm_store_si128(output + 9, xout5);
	_mm_store_si128(output + 10, xout6);
	_mm_store_si128(output + 11, xout7);
}

template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0)
{
	keccak((const uint8_t *)input, len, ctx0->hash_state, 200);

	// Optim - 99% time boundary
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);

	uint8_t* l0 = ctx0->long_state;
	uint64_t* h0 = (uint64_t*)ctx0->hash_state;

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	__m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

	uint64_t idx0 = h0[0] ^ h0[4];

	// Optim - 90% time boundary
	for(size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = _mm_load_si128((__m128i *)&l0[idx0 & 0x1FFFF0]);

		if(SOFT_AES)
			cx = soft_aesenc(cx, _mm_set_epi64x(ah0, al0));
		else
			cx = _mm_aesenc_si128(cx, _mm_set_epi64x(ah0, al0));

		_mm_store_si128((__m128i *)&l0[idx0 & 0x1FFFF0], _mm_xor_si128(bx0, cx));
		idx0 = _mm_cvtsi128_si64(cx);
		bx0 = cx;

		if(PREFETCH)
			_mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
		ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

		lo = _umul128(idx0, cl, &hi);

		al0 += hi;
		ah0 += lo;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = al0;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = ah0;
		ah0 ^= ch;
		al0 ^= cl;
		idx0 = al0;

		if(PREFETCH)
			_mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);
	}

	// Optim - 90% time boundary
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);

	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx0->hash_state, 24);
	extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx* __restrict ctx0, cryptonight_ctx* __restrict ctx1, cryptonight_ctx* __restrict ctx2, cryptonight_ctx* __restrict ctx3, cryptonight_ctx* __restrict ctx4, cryptonight_ctx* __restrict ctx5, cryptonight_ctx* __restrict ctx6, cryptonight_ctx* __restrict ctx7)
{
	keccak((const uint8_t *)input, len, ctx0->hash_state, 200);
	keccak((const uint8_t *)input+len, len, ctx1->hash_state, 200);
	keccak((const uint8_t *)input+(2*len), len, ctx2->hash_state, 200);
	keccak((const uint8_t *)input+(3*len), len, ctx3->hash_state, 200);
	keccak((const uint8_t *)input+(4*len), len, ctx4->hash_state, 200);
	keccak((const uint8_t *)input+(5*len), len, ctx5->hash_state, 200);
	keccak((const uint8_t *)input+(6*len), len, ctx6->hash_state, 200);
	keccak((const uint8_t *)input+(7*len), len, ctx7->hash_state, 200);

	// Optim - 99% time boundary
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx2->hash_state, (__m128i*)ctx2->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx3->hash_state, (__m128i*)ctx3->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx4->hash_state, (__m128i*)ctx4->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx5->hash_state, (__m128i*)ctx5->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx6->hash_state, (__m128i*)ctx6->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx7->hash_state, (__m128i*)ctx7->long_state);

	uint8_t* l0 = ctx0->long_state;
	uint64_t* h0 = (uint64_t*)ctx0->hash_state;
	uint8_t* l1 = ctx1->long_state;
	uint64_t* h1 = (uint64_t*)ctx1->hash_state;
	uint8_t* l2 = ctx2->long_state;
	uint64_t* h2 = (uint64_t*)ctx2->hash_state;
	uint8_t* l3 = ctx3->long_state;
	uint64_t* h3 = (uint64_t*)ctx3->hash_state;
	uint8_t* l4 = ctx4->long_state;
	uint64_t* h4 = (uint64_t*)ctx4->hash_state;
	uint8_t* l5 = ctx5->long_state;
	uint64_t* h5 = (uint64_t*)ctx5->hash_state;
	uint8_t* l6 = ctx6->long_state;
	uint64_t* h6 = (uint64_t*)ctx6->hash_state;
	uint8_t* l7 = ctx7->long_state;
	uint64_t* h7 = (uint64_t*)ctx7->hash_state;

	uint64_t axl0 = h0[0] ^ h0[4];
	uint64_t axh0 = h0[1] ^ h0[5];
	__m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
	uint64_t axl1 = h1[0] ^ h1[4];
	uint64_t axh1 = h1[1] ^ h1[5];
	__m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
	__m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
	__m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
	__m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
	__m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
	__m128i ax4 = _mm_set_epi64x(h4[1] ^ h4[5], h4[0] ^ h4[4]);
	__m128i bx4 = _mm_set_epi64x(h4[3] ^ h4[7], h4[2] ^ h4[6]);
	__m128i ax5 = _mm_set_epi64x(h5[1] ^ h5[5], h5[0] ^ h5[4]);
	__m128i bx5 = _mm_set_epi64x(h5[3] ^ h5[7], h5[2] ^ h5[6]);
	__m128i ax6 = _mm_set_epi64x(h6[1] ^ h6[5], h6[0] ^ h6[4]);
	__m128i bx6 = _mm_set_epi64x(h6[3] ^ h6[7], h6[2] ^ h6[6]);
	__m128i ax7 = _mm_set_epi64x(h7[1] ^ h7[5], h7[0] ^ h7[4]);
	__m128i bx7 = _mm_set_epi64x(h7[3] ^ h7[7], h7[2] ^ h7[6]);

	uint64_t idx0 = h0[0] ^ h0[4];
	uint64_t idx1 = h1[0] ^ h1[4];
	uint64_t idx2 = h2[0] ^ h2[4];
	uint64_t idx3 = h3[0] ^ h3[4];
	uint64_t idx4 = h4[0] ^ h4[4];
	uint64_t idx5 = h5[0] ^ h5[4];
	uint64_t idx6 = h6[0] ^ h6[4];
	uint64_t idx7 = h7[0] ^ h7[4];

	// Optim - 90% time boundary
	for (size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = _mm_load_si128((__m128i *)&l0[idx0 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax0);
		_mm_store_si128((__m128i *)&l0[idx0 & 0x1FFFF0], _mm_xor_si128(bx0, cx));
		idx0 = _mm_cvtsi128_si64(cx);
		bx0 = cx;
		_mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l1[idx1 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax1);
		_mm_store_si128((__m128i *)&l1[idx1 & 0x1FFFF0], _mm_xor_si128(bx1, cx));
		idx1 = _mm_cvtsi128_si64(cx);
		bx1 = cx;
		_mm_prefetch((const char*)&l1[idx1 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l2[idx2 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax2);
		_mm_store_si128((__m128i *)&l2[idx2 & 0x1FFFF0], _mm_xor_si128(bx2, cx));
		idx2 = _mm_cvtsi128_si64(cx);
		bx2 = cx;
		_mm_prefetch((const char*)&l2[idx2 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l3[idx3 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax3);
		_mm_store_si128((__m128i *)&l3[idx3 & 0x1FFFF0], _mm_xor_si128(bx3, cx));
		idx3 = _mm_cvtsi128_si64(cx);
		bx3 = cx;
		_mm_prefetch((const char*)&l3[idx3 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l4[idx4 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax4);
		_mm_store_si128((__m128i *)&l4[idx4 & 0x1FFFF0], _mm_xor_si128(bx4, cx));
		idx4 = _mm_cvtsi128_si64(cx);
		bx4 = cx;
		_mm_prefetch((const char*)&l4[idx4 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l5[idx5 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax5);
		_mm_store_si128((__m128i *)&l5[idx5 & 0x1FFFF0], _mm_xor_si128(bx5, cx));
		idx5 = _mm_cvtsi128_si64(cx);
		bx5 = cx;
		_mm_prefetch((const char*)&l5[idx5 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l6[idx6 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax6);
		_mm_store_si128((__m128i *)&l6[idx6 & 0x1FFFF0], _mm_xor_si128(bx6, cx));
		idx6 = _mm_cvtsi128_si64(cx);
		bx6 = cx;
		_mm_prefetch((const char*)&l6[idx6 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l7[idx7 & 0x1FFFF0]);
		cx = _mm_aesenc_si128(cx, ax7);
		_mm_store_si128((__m128i *)&l7[idx7 & 0x1FFFF0], _mm_xor_si128(bx7, cx));
		idx7 = _mm_cvtsi128_si64(cx);
		bx7 = cx;
		_mm_prefetch((const char*)&l7[idx7 & 0x1FFFF0], _MM_HINT_T1);

		uint64_t hi, lo;
		cx = _mm_load_si128((__m128i *)&l0[idx0 & 0x1FFFF0]);
		lo = _umul128(idx0, _mm_cvtsi128_si64(cx), &hi);
		ax0 = _mm_add_epi64(ax0, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l0[idx0 & 0x1FFFF0], ax0);
		ax0 = _mm_xor_si128(ax0, cx);
		idx0 = _mm_cvtsi128_si64(ax0);
		_mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l1[idx1 & 0x1FFFF0]);
		lo = _umul128(idx1, _mm_cvtsi128_si64(cx), &hi);
		ax1 = _mm_add_epi64(ax1, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l1[idx1 & 0x1FFFF0], ax1);
		ax1 = _mm_xor_si128(ax1, cx);
		idx1 = _mm_cvtsi128_si64(ax1);
		_mm_prefetch((const char*)&l1[idx1 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l2[idx2 & 0x1FFFF0]);
		lo = _umul128(idx2, _mm_cvtsi128_si64(cx), &hi);
		ax2 = _mm_add_epi64(ax2, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l2[idx2 & 0x1FFFF0], ax2);
		ax2 = _mm_xor_si128(ax2, cx);
		idx2 = _mm_cvtsi128_si64(ax2);
		_mm_prefetch((const char*)&l2[idx2 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l3[idx3 & 0x1FFFF0]);
		lo = _umul128(idx3, _mm_cvtsi128_si64(cx), &hi);
		ax3 = _mm_add_epi64(ax3, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l3[idx3 & 0x1FFFF0], ax3);
		ax3 = _mm_xor_si128(ax3, cx);
		idx3 = _mm_cvtsi128_si64(ax3);
		_mm_prefetch((const char*)&l3[idx3 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l4[idx4 & 0x1FFFF0]);
		lo = _umul128(idx4, _mm_cvtsi128_si64(cx), &hi);
		ax4 = _mm_add_epi64(ax4, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l4[idx4 & 0x1FFFF0], ax4);
		ax4 = _mm_xor_si128(ax4, cx);
		idx4 = _mm_cvtsi128_si64(ax4);
		_mm_prefetch((const char*)&l4[idx4 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l5[idx5 & 0x1FFFF0]);
		lo = _umul128(idx5, _mm_cvtsi128_si64(cx), &hi);
		ax5 = _mm_add_epi64(ax5, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l5[idx5 & 0x1FFFF0], ax5);
		ax5 = _mm_xor_si128(ax5, cx);
		idx5 = _mm_cvtsi128_si64(ax5);
		_mm_prefetch((const char*)&l5[idx5 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l6[idx6 & 0x1FFFF0]);
		lo = _umul128(idx6, _mm_cvtsi128_si64(cx), &hi);
		ax6 = _mm_add_epi64(ax6, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l6[idx6 & 0x1FFFF0], ax6);
		ax6 = _mm_xor_si128(ax6, cx);
		idx6 = _mm_cvtsi128_si64(ax6);
		_mm_prefetch((const char*)&l6[idx6 & 0x1FFFF0], _MM_HINT_T1);

		cx = _mm_load_si128((__m128i *)&l7[idx7 & 0x1FFFF0]);
		lo = _umul128(idx7, _mm_cvtsi128_si64(cx), &hi);
		ax7 = _mm_add_epi64(ax7, _mm_set_epi64x(lo, hi));
		_mm_store_si128((__m128i*)&l7[idx7 & 0x1FFFF0], ax7);
		ax7 = _mm_xor_si128(ax7, cx);
		idx7 = _mm_cvtsi128_si64(ax7);
		_mm_prefetch((const char*)&l7[idx7 & 0x1FFFF0], _MM_HINT_T1);
	}

	// Optim - 90% time boundary
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx2->long_state, (__m128i*)ctx2->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx3->long_state, (__m128i*)ctx3->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx4->long_state, (__m128i*)ctx4->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx5->long_state, (__m128i*)ctx5->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx6->long_state, (__m128i*)ctx6->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx7->long_state, (__m128i*)ctx7->hash_state);

	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx0->hash_state, 24);
	extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
	keccakf((uint64_t*)ctx1->hash_state, 24);
	extra_hashes[ctx1->hash_state[0] & 3](ctx1->hash_state, 200, (char*)output + 32);
	keccakf((uint64_t*)ctx2->hash_state, 24);
	extra_hashes[ctx2->hash_state[0] & 3](ctx2->hash_state, 200, (char*)output + 32*2);
	keccakf((uint64_t*)ctx3->hash_state, 24);
	extra_hashes[ctx3->hash_state[0] & 3](ctx3->hash_state, 200, (char*)output + 32*3);
	keccakf((uint64_t*)ctx4->hash_state, 24);
	extra_hashes[ctx4->hash_state[0] & 3](ctx4->hash_state, 200, (char*)output + 32*4);
	keccakf((uint64_t*)ctx5->hash_state, 24);
	extra_hashes[ctx5->hash_state[0] & 3](ctx5->hash_state, 200, (char*)output + 32*5);
	keccakf((uint64_t*)ctx6->hash_state, 24);
	extra_hashes[ctx6->hash_state[0] & 3](ctx6->hash_state, 200, (char*)output + 32*6);
	keccakf((uint64_t*)ctx7->hash_state, 24);
	extra_hashes[ctx7->hash_state[0] & 3](ctx7->hash_state, 200, (char*)output + 32*7);
}
