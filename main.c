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

#include <string.h>
#include "ctr_drbg.h"
#include "test_utilities.h"

#ifdef PERF
  #include "measurements.h"
#endif

// NIST maximal allowed lengths as observed in the NIST .txt file
// The values belows represents bytes
// When the name contain the string 'bits' it is only for consistency with NIST KATs
#define NIST_TEST_COUNT 15
#define MAX_NONCE_LEN 0
#define MAX_V_LEN (AES256_KEY_SIZE/2)
#define MAX_ENTROPY_LEN (MAX_V_LEN + AES256_KEY_SIZE)
#define MAX_ADITIONAL_INPUT_LEN (512/8)
#define MAX_RETURNED_BITS_LEN (512/8)
#define MAX_PERSONALIZATION_STRING_LEN (512/8)

#define MAX_MEASURE_LEN ((1 << 15) + 32)
typedef struct entropy_s
{
    uint8_t  raw[CTR_DRBG_ENTROPY_LEN];
} entropy_t;

#ifdef PERF
_INLINE_ int measure()
{
    CTR_DRBG_STATE drbg;
    uint8_t  entropy_in[MAX_ENTROPY_LEN] = {0};
    uint8_t  personalization_string[1] = {0};
    uint8_t  drbg_out[MAX_MEASURE_LEN] = {0};
    uint8_t  additional_in[1] = {0};

    CTR_DRBG_init(&drbg, entropy_in, personalization_string, 0);
#ifdef COUNT_INSTRUCTIONS
    MEASURE("CTR_DRBG_generate", CTR_DRBG_generate(&drbg, drbg_out, ( 1 << 10), additional_in, 0););
#else
    for(uint32_t i = PAR_AES_BLOCK_SIZE ; i < MAX_MEASURE_LEN; i <<= 1)
    {
        printf("i=%d: ", i);
        MEASURE("CTR_DRBG_generate", CTR_DRBG_generate(&drbg, drbg_out, i, additional_in, 0););
    }
#endif
    CTR_DRBG_clear(&drbg);
    
    return SUCCESS;
}

#else // PERF
_INLINE_ int test_ctr_drbg_init(FILE *f, 
                                CTR_DRBG_STATE *drbg,
                                const uint32_t entropy_in_len,
                                const uint32_t nonce_len,
                                const uint32_t personalization_string_len)
{
    uint32_t count = 0;
    uint8_t  entropy_in[MAX_ENTROPY_LEN] = {0};
    uint8_t  nonce[MAX_NONCE_LEN+1] = {0};
    uint8_t  personalization_string[MAX_PERSONALIZATION_STRING_LEN] = {0};
    uint8_t  key[AES256_KEY_SIZE] = {0};
    uint8_t  v[MAX_V_LEN] = {0};

    // Prepare (read txt file)
    GUARD(read_uint_in_bytes(f, &count, "COUNT = %u\n"));
    GUARD(read_hex(f, entropy_in, "EntropyInput = ", entropy_in_len));
    GUARD(read_hex(f, nonce, "Nonce = ", nonce_len));
    GUARD(read_hex(f, personalization_string, "PersonalizationString = ", 
                   personalization_string_len));

    GUARD(read_op(f, "** INSTANTIATE:\n"));
    GUARD(read_hex(f, key, "Key = ", AES256_KEY_SIZE));
    GUARD(read_hex(f, v,   "V   = ", MAX_V_LEN));

    entropy_t entropy = {{0}};
    memcpy(entropy.raw, entropy_in, entropy_in_len);
    memcpy(&entropy.raw[entropy_in_len], nonce, nonce_len);

    // Run
    CTR_DRBG_init(drbg, entropy.raw, personalization_string, 
                  personalization_string_len);
    
    // Test
    GUARD(equal((uint8_t*)&drbg->ks, key, AES256_KEY_SIZE));
    GUARD(equal(drbg->counter.bytes, v, sizeof(drbg->counter)));

    return SUCCESS;
}

_INLINE_ int test_ctr_drbg_reseed(FILE *f,
                                  CTR_DRBG_STATE *drbg,
                                  const uint32_t entropy_in_len,
                                  const uint32_t additional_in_len)
{
    uint8_t  entropy_in_reseed[MAX_ENTROPY_LEN] = {0};
    uint8_t  additional_in_reseed[MAX_ADITIONAL_INPUT_LEN] = {0};
    uint8_t  key[AES256_KEY_SIZE] = {0};
    uint8_t  v[MAX_V_LEN] = {0};

    // Prepare
    GUARD(read_hex(f, entropy_in_reseed, "EntropyInputReseed = ", 
                   entropy_in_len));
    GUARD(read_hex(f, additional_in_reseed, "AdditionalInputReseed = ", 
                   additional_in_len));

    GUARD(read_op(f, "** RESEED:\n"));
    GUARD(read_hex(f, key, "Key = ", AES256_KEY_SIZE));
    GUARD(read_hex(f, v,   "V   = ", MAX_V_LEN));
    
    // Run
    CTR_DRBG_reseed(drbg, entropy_in_reseed, 
                    additional_in_reseed, additional_in_len);
    
    // Test
    GUARD(equal((uint8_t*)&drbg->ks, key, AES256_KEY_SIZE));
    GUARD(equal(drbg->counter.bytes, v, sizeof(drbg->counter)));
    return SUCCESS;
}

_INLINE_ int test_ctr_drbg_gen1(FILE *f,
                                CTR_DRBG_STATE *drbg,                                
                                const uint32_t additional_in_len)
{
    uint8_t additional_in[MAX_ADITIONAL_INPUT_LEN] = {0};
    uint8_t key[AES256_KEY_SIZE] = {0};
    uint8_t v[MAX_V_LEN] = {0};
    uint8_t drbg_out[MAX_RETURNED_BITS_LEN] = {0};

    // Prepare
    GUARD(read_hex(f, additional_in, "AdditionalInput = ", additional_in_len));
    GUARD(read_op(f, "** GENERATE (FIRST CALL):\n"));
    GUARD(read_hex(f, key, "Key = ", AES256_KEY_SIZE));
    GUARD(read_hex(f, v,   "V   = ", MAX_V_LEN));

    // Run
    CTR_DRBG_generate(drbg, drbg_out, MAX_RETURNED_BITS_LEN, 
                      additional_in, additional_in_len);

    // Test
    GUARD(equal((uint8_t*)&drbg->ks, key, AES256_KEY_SIZE));
    GUARD(equal(drbg->counter.bytes, v, sizeof(drbg->counter)));

    return SUCCESS;
}

_INLINE_ int test_ctr_drbg_gen2(FILE *f, 
                                CTR_DRBG_STATE *drbg,
                                const uint32_t additional_in_len, 
                                const uint32_t returned_bits_len)
{
    uint8_t additional_in[MAX_ADITIONAL_INPUT_LEN] = {0};
    uint8_t key[AES256_KEY_SIZE] = {0};
    uint8_t v[MAX_V_LEN] = {0};
    uint8_t returned_bits[MAX_RETURNED_BITS_LEN] = {0};
    uint8_t drbg_out[MAX_RETURNED_BITS_LEN] = {0};

    // Prepare
    GUARD(read_hex(f, additional_in, "AdditionalInput = ", additional_in_len));
    GUARD(read_hex(f, returned_bits, "ReturnedBits = ", returned_bits_len));
    GUARD(read_op(f, "** GENERATE (SECOND CALL):\n"));
    GUARD(read_hex(f, key, "Key = ", AES256_KEY_SIZE));
    GUARD(read_hex(f, v,   "V   = ", MAX_V_LEN));

    // Run
    CTR_DRBG_generate(drbg, drbg_out, MAX_RETURNED_BITS_LEN, 
                      additional_in, additional_in_len);
    
    // Test
    GUARD(equal((uint8_t*)&drbg->ks, key, AES256_KEY_SIZE));
    GUARD(equal(drbg->counter.bytes, v, sizeof(drbg->counter)));
    GUARD(equal(drbg_out, returned_bits, returned_bits_len));
    
    return SUCCESS;
}

_INLINE_ int test_kats()
{
    CTR_DRBG_STATE drbg;

    pr_t pr;
    uint32_t entropy_in_len = 0;
    uint32_t nonce_len = 0;
    uint32_t personalization_string_len = 0;
    uint32_t additional_in_len = 0;
    uint32_t returned_bits_len = 0;

    FILE *txt_fp = fopen("KATs/CTR_DRBG_pr_false.txt", "r"); // read mode

    if (NULL == txt_fp)
    {
        perror("Error while opening the file.\n");
        return 1;
    }

    while ((!feof(txt_fp)) && 
           (SUCCESS == goto_AES256_test(txt_fp, "[AES-256 no df]\n")))
    { 
        GUARD(read_pr(txt_fp, &pr));
        GUARD(read_uint_in_bytes(txt_fp, &entropy_in_len, 
                                 "[EntropyInputLen = %u]\n"));
        GUARD(read_uint_in_bytes(txt_fp, &nonce_len, "[NonceLen = %u]\n"));
        GUARD(read_uint_in_bytes(txt_fp, &personalization_string_len, 
                                 "[PersonalizationStringLen = %u]\n"));
        GUARD(read_uint_in_bytes(txt_fp, &additional_in_len, 
                                 "[AdditionalInputLen = %u]\n"));
        GUARD(read_uint_in_bytes(txt_fp, &returned_bits_len, 
                                 "[ReturnedBitsLen = %u]\n"));
        
        if((nonce_len > MAX_NONCE_LEN) ||
           (entropy_in_len > MAX_ENTROPY_LEN) ||
           (additional_in_len > MAX_ADITIONAL_INPUT_LEN) ||
           (returned_bits_len > MAX_RETURNED_BITS_LEN) || 
           (personalization_string_len > MAX_PERSONALIZATION_STRING_LEN))
        {
            printf("ERROR: length is too big\n");
            return ERROR;
        }

        if(entropy_in_len + nonce_len > sizeof(entropy_t))
        {
            printf("ERROR: (entropy_in_len + nonce_len) will cause overflow\n");
            return ERROR;
        }

        for(uint8_t i=0 ; i < NIST_TEST_COUNT; i++)
        {
            GUARD(test_ctr_drbg_init(txt_fp, &drbg, entropy_in_len, 
                                     nonce_len, personalization_string_len));
            
            GUARD(test_ctr_drbg_reseed(txt_fp, &drbg, entropy_in_len, 
                                       additional_in_len));
            
            GUARD(test_ctr_drbg_gen1(txt_fp, &drbg, additional_in_len));
            
            GUARD(test_ctr_drbg_gen2(txt_fp, &drbg, additional_in_len, 
                                     returned_bits_len));
            
            CTR_DRBG_clear(&drbg);
        }
    }
    fclose(txt_fp);

    printf("All tests passed.\n");

    return SUCCESS;
}

#endif // PERF

int main()
{
#ifdef PERF
    return measure();
#else
    return test_kats();
#endif
}
