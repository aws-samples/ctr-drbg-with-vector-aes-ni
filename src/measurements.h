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

#ifdef COUNT_INSTRUCTIONS

   #define START_MARK 1  //defines sde marks
   #define END_MARK   2

   #ifndef __SSC_MARK
       static inline void SSC_MARK(unsigned int mark_id)
       {
          __asm__ __volatile__ ("movl %0, %%ebx; .byte 0x64, 0x67, 0x90 " ::"i"(mark_id):"%ebx");   
       }
 
       #define __SSC_MARK(x) SSC_MARK(x)
   #endif

   #define MEASURE(msg, x)              \
                __SSC_MARK(START_MARK); \
                    x;                  \
                __SSC_MARK(END_MARK);

#else //COUNT_INSTRUCTIONS

#define MAX_DOUBLE_VALUE 1.7976931348623157e+308

#ifndef REPEAT     
    #define REPEAT 1000
#endif

#ifndef OUTER_REPEAT
    #define OUTER_REPEAT 30
#endif

#ifndef WARMUP
    #define WARMUP REPEAT/4
#endif

unsigned long long RDTSC_start_clk, RDTSC_end_clk;
double RDTSC_total_clk;
double RDTSC_TEMP_CLK;
int RDTSC_MEASURE_ITERATOR;
int RDTSC_OUTER_ITERATOR;

inline static uint64_t get_Clks(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
    return ( (uint64_t)lo)^( ((uint64_t)hi)<<32 );
}

/* 
This MACRO measures the number of cycles "x" runs. This is the flow:
    2) it repeats "x" WARMUP times, in order to warm the cache.
    3) it reads the Time Stamp Counter at the beginning of the test.
    4) it repeats "x" REPEAT number of times.
    5) it reads the Time Stamp Counter again at the end of the test
    6) it calculates the average number of cycles per one iteration of "x", by calculating the total number of cycles, and dividing it by REPEAT
*/      
#define RDTSC_MEASURE(msg, x)                                                                     \
for(RDTSC_MEASURE_ITERATOR=0; RDTSC_MEASURE_ITERATOR< WARMUP; RDTSC_MEASURE_ITERATOR++)           \
    {                                                                                             \
        {x};                                                                                      \
    }                                                                                             \
RDTSC_total_clk = MAX_DOUBLE_VALUE;                                                               \
for(RDTSC_OUTER_ITERATOR=0;RDTSC_OUTER_ITERATOR<OUTER_REPEAT; RDTSC_OUTER_ITERATOR++){            \
    RDTSC_start_clk = get_Clks();                                                                 \
    for (RDTSC_MEASURE_ITERATOR = 0; RDTSC_MEASURE_ITERATOR < REPEAT; RDTSC_MEASURE_ITERATOR++)   \
    {                                                                                             \
        {x};                                                                                      \
    }                                                                                             \
    RDTSC_end_clk = get_Clks();                                                                   \
    RDTSC_TEMP_CLK = (double)(RDTSC_end_clk-RDTSC_start_clk)/REPEAT;                              \
    if(RDTSC_total_clk>RDTSC_TEMP_CLK) RDTSC_total_clk = RDTSC_TEMP_CLK;                          \
} \
printf("%s", msg); \
printf(" took %0.2f cycles\n", RDTSC_total_clk );

#define MEASURE(msg, x) RDTSC_MEASURE(msg, x)

#endif //COUNT_INSTRUCTIONS
