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

#include <ctype.h>
#include <string.h>
#include "test_utilities.h"

#define MAX_BUFFER_SIZE 512

_INLINE_ void skip_spaces(IN OUT FILE *f)
{
    char c = ' ';
    while ((!feof(f)) && (isspace(c)))
    {
        c = fgetc(f);
    }

    ungetc(c, f);
}

status_t goto_AES256_test(IN OUT FILE *f, 
                          IN const char* str)
{
    char buffer[MAX_BUFFER_SIZE] = {0};
    while (!feof(f))
    {
        if (!fgets(buffer, sizeof(buffer), f)) {
            return ERROR;
        }
        if (0 == strcmp(buffer, str)) {
            return SUCCESS;
        }
    }

    return ERROR;
}

status_t read_op(IN OUT FILE *f, 
                 IN const char* str)
{
    char buffer[MAX_BUFFER_SIZE] = {0};
    
    skip_spaces(f);
    if (NULL == fgets(buffer, sizeof(buffer), f))
    {
        printf("fgets failed in read_op %s\n", str);
        return ERROR;
    }

    if (0 != strcmp(buffer, str))
    {
        printf("buffer %s does not equal %s\n", buffer, str);
        return ERROR;
    }

    return SUCCESS;
}

status_t read_pr(IN OUT FILE *f, 
                 OUT pr_t* pr)
{
    char buffer[MAX_BUFFER_SIZE] = {0};
    if (NULL == fgets(buffer, sizeof(buffer), f))
    {
        return ERROR;
    }

    if (strcmp(buffer, "[PredictionResistance = False]"))
    {
        *pr = NoPredictionResistance;
        return SUCCESS;
    }
    else if (strcmp(buffer, "[PredictionResistance = True]"))
    {
        *pr = PredictionResistance;
        return SUCCESS;
    }

    return ERROR;
}

status_t read_uint_in_bytes(IN OUT FILE *f, 
                            OUT uint32_t* val, 
                            IN const char* str)
{
    skip_spaces(f);
    if (!fscanf(f, str, val))
    {
            printf("Error reading %s\n", str);
            return ERROR;
    }

    // Convert to bytes
    *val >>= 3;
    
    return SUCCESS;
}

status_t read_hex(IN OUT FILE *f, 
                  OUT uint8_t *val, 
                  IN const char *prefix, 
                  IN const unsigned int len)
{
    char buffer[MAX_BUFFER_SIZE];

    skip_spaces(f);
    if (NULL == fgets(buffer, strlen(prefix) + 1, f))
    {
        printf("Cant read %s\n", prefix);
        return ERROR;
    }

    if (strcmp(buffer, prefix))
    {
        printf("Buffer %s does not match %s\n", buffer, prefix);
        return ERROR;
    }

    for (uint32_t i = 0; i < len; i++)
    {
        //"%02hhx" stands for reading one hex value at a time.
        if (0 == fscanf(f, "%02hhx", &val[i]))
        {
            printf("read_hex for prefix %s, scanf error %d \n", prefix, i);
            return ERROR;
        }
    }
    
    return SUCCESS;
}

status_t equal(IN const uint8_t* a, 
               IN const uint8_t* b, 
               IN const uint32_t len)
{
    if (0 == memcmp(a,b,len))
    {
        return SUCCESS;
    }

    return ERROR;
}

void print_BE(IN const uint8_t *in, 
              IN const uint32_t len)
{
    // Print each 8 bytes separated by space (if required)
    for (uint32_t i = 0; i < len; i++)
    {
        printf("%.2x", in[i]);
    }

    printf("\n");
}
