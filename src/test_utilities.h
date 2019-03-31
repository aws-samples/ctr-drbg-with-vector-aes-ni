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

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "defs.h"

typedef enum
{
  PredictionResistance=0,
  NoPredictionResistance
} pr_t;

status_t goto_AES256_test(IN OUT FILE *f, 
                          IN const char* str);

status_t read_op(IN OUT FILE *f, 
                 IN const char* str);

status_t read_pr(IN OUT FILE *f, 
                 OUT pr_t* pr);

status_t read_uint_in_bytes(IN OUT FILE *f, 
                            OUT uint32_t* val, 
                            IN const char* str);

status_t read_hex(IN OUT FILE *f, 
                  OUT uint8_t *val, 
                  IN const char *prefix, 
                  IN const uint32_t len);

status_t equal(IN const uint8_t* a, 
               IN const uint8_t* b, 
               IN const uint32_t len);

void print_BE(IN const uint8_t *in, 
              IN const uint32_t len);
