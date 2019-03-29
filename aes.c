/***************************************************************************
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*  
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*  
*     http://www.apache.org/licenses/LICENSE-2.0
*  
* or in the "license" file accompanying this file. This file is distributed 
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
* express or implied. See the License for the specific language governing 
* permissions and limitations under the License.
* The license is detailed in the file LICENSE.txt, and applies to this file.
* ***************************************************************************/

#include "aes.h"
#include <string.h>

#include <immintrin.h>

#define AESENC(m, key)         _mm_aesenc_si128(m, key)
#define AESENCLAST(m, key)     _mm_aesenclast_si128(m, key)
#define XOR(a, b)              _mm_xor_si128(a, b)
#define ADD32(a, b)            _mm_add_epi32(a, b)
#define SHUF8(a, mask)         _mm_shuffle_epi8(a, mask)

#define BSWAP_MASK 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f

#ifdef VAES
#define VAESENC(a, key)        _mm512_aesenc_epi128(a, key)
#define VAESENCLAST(a, key)    _mm512_aesenclast_epi128(a, key)
#define EXTRACT128(a, imm)     _mm512_extracti64x2_epi64(a, imm)
#define XOR512(a, b)           _mm512_xor_si512(a,b)
#define ADD32_512(a, b)        _mm512_add_epi32(a,b)
#define SHUF8_512(a, mask)     _mm512_shuffle_epi8(a, mask)
#endif

_INLINE_ __m128i load_m128i(IN const uint8_t *ctr)
{
    return _mm_set_epi8(ctr[0],  ctr[1],  ctr[2],  ctr[3],
                        ctr[4],  ctr[5],  ctr[6],  ctr[7],
                        ctr[8],  ctr[9],  ctr[10], ctr[11],
                        ctr[12], ctr[13], ctr[14], ctr[15]);
}

_INLINE_ __m128i loadr_m128i(IN const uint8_t *ctr)
{
    return _mm_setr_epi8(ctr[0],  ctr[1],  ctr[2],  ctr[3],
                         ctr[4],  ctr[5],  ctr[6],  ctr[7],
                         ctr[8],  ctr[9],  ctr[10], ctr[11],
                         ctr[12], ctr[13], ctr[14], ctr[15]);
}

void aes256_enc(OUT uint8_t *ct,
                IN const uint8_t *pt,
                IN const aes256_ks_t *ks) {
    uint32_t i = 0;
    __m128i block = loadr_m128i(pt);

    block = XOR(block, ks->keys[0]);
    for (i = 1; i < AES256_ROUNDS; i++) {
        block = AESENC(block, ks->keys[i]);
    }
    block = AESENCLAST(block, ks->keys[AES256_ROUNDS]);

    _mm_storeu_si128((void*)ct, block);

    // Delete secrets from registers if any.
    _mm256_zeroall();
}

void aes256_ctr_enc(OUT uint8_t *ct,
                    IN const uint8_t *ctr,
                    IN const uint64_t num_blocks,
                    IN const aes256_ks_t *ks)
{
    uint32_t i = 0;
    __m128i ctr_block = load_m128i(ctr);

    const __m128i bswap_mask = _mm_set_epi32(BSWAP_MASK);
    const __m128i one = _mm_set_epi32(0,0,0,1);

    __m128i block = SHUF8(ctr_block, bswap_mask);

    for (uint32_t bidx = 0; bidx < num_blocks; bidx++) 
    {
        block = XOR(block, ks->keys[0]);
        for (i = 1; i < AES256_ROUNDS; i++) {
            block = AESENC(block, ks->keys[i]);
        }
        block = AESENCLAST(block, ks->keys[AES256_ROUNDS]);

        //We use memcpy to avoid align casting.
        _mm_storeu_si128((void*)&ct[16*bidx], block);

        ctr_block = ADD32(ctr_block, one);
        block = SHUF8(ctr_block, bswap_mask);
    }
    
    // Delete secrets from registers if any.
    _mm256_zeroall();
}

#ifdef VAES

_INLINE_ void load_ks(OUT __m512i ks512[AES256_ROUNDS + 1], 
                      IN const aes256_ks_t *ks)
{
    for(uint32_t i = 0; i < AES256_ROUNDS + 1; i++)
    {
        ks512[i] = _mm512_broadcast_i32x4(ks->keys[i]);
    }
}

void aes256_ctr_enc512(OUT uint8_t *ct,
                       IN const uint8_t *ctr,
                       IN const uint64_t num_blocks,
                       IN const aes256_ks_t *ks)
{
    const uint64_t num_par_blocks = num_blocks/4;
    const uint64_t blocks_rem = num_blocks - (4*(num_par_blocks));

    __m512i ks512[AES256_ROUNDS + 1];
    load_ks(ks512, ks);

    __m128i single_block = load_m128i(ctr);
    __m512i ctr_blocks = _mm512_broadcast_i32x4(single_block);

    // Preparing the masks
    const __m512i bswap_mask = _mm512_set_epi32(BSWAP_MASK, BSWAP_MASK,
                                                BSWAP_MASK, BSWAP_MASK);
    const __m512i four = _mm512_set_epi32(0,0,0,4,0,0,0,4,0,0,0,4,0,0,0,4);
    const __m512i init = _mm512_set_epi32(0,0,0,3,0,0,0,2,0,0,0,1,0,0,0,0);

    // Initialize four parallel counters
    ctr_blocks = ADD32_512(ctr_blocks, init);
    __m512i p = SHUF8_512(ctr_blocks, bswap_mask);

    for (uint32_t block_idx = 0; block_idx < num_par_blocks; block_idx++) 
    {
        p = XOR512(p, ks512[0]);
        for (uint32_t i = 1; i < AES256_ROUNDS; i++) 
        {
            p = VAESENC(p, ks512[i]);
        }
        p = VAESENCLAST(p, ks512[AES256_ROUNDS]);


        // We use memcpy to avoid align casting.
        _mm512_storeu_si512(&ct[PAR_AES_BLOCK_SIZE * block_idx], p);

        // Increase the four counters in parallel
        ctr_blocks = ADD32_512(ctr_blocks, four);
        p = SHUF8_512(ctr_blocks, bswap_mask);
    }
 
    if(0 != blocks_rem)
    {
        single_block = EXTRACT128(p, 0);
        aes256_ctr_enc(&ct[PAR_AES_BLOCK_SIZE * num_par_blocks], 
                       (const uint8_t*)&single_block, blocks_rem, ks);
    }

    // Delete secrets from registers if any.
    _mm256_zeroall();
}

#endif //VAES
