## CTR DRBG with vector AES NI

This repository provides a CTR DRBG that leverages the (currently forthcoming) 
Vector AES_NI instructions [1][2]. These instructions perform one round of AES 
encryption/decryption on 1/2/4 128-bit operands and they receive a plaintext/
ciphertext block and a round key as their inputs.

Here is some motivation. Multiple NIST Post Quantum Cryptography Project candidates use DRBG. 
Thus, they also (at least implicitly) rely on the performance of the DRBG implementation. 
The goal of this package is to provide NIST and the cryptographic community with a fast COUNTER DRBG
that leverages the new vectorized AES instructions (soon to come out).
This would allow the community to better evaluate the schemes performance on the near future CPUs.

Real Icelake (and Intel microarchitecture) samples are not yet available. 
Therefore, we used the Intel Software Developer Emulator (SDE) to predict the potential improvement 
on future architectures. The prediction is based on counting the number of instructions of the 
CTR_DRBG_generate with and without the new instructions. 
The rationale is that a reduced number of instructions typically indicates improved performance (although the exact 
relation is not known in advanced). The results could be validated as soon as real CPU's with this capability come out
to the market. 

The CTR DRBG portion of the code (ctr_drbg.c/h) is taken from BoringSSL 
(with almost no changes). This DRBG does not use derivation functions 
or prediction resistant.

The executable has three flavors:
1) Validation (default) – uses the test vectors of the Cryptographic Algorithm 
   Validation Program (CAVP) of NIST 
   [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program] 
   to verify the CTR DRBG code. The relevant KATs are copied into the KAT directory.
2) Measure the DRBG performance.
3) Count the number of instructions of the CTR_DRBG_generate 
   function (see instructions below).

## License

This code was written by Nir Drucker and Shay Gueron
AWS Cryptographic Algorithms Group
(ndrucker@amazon.com, gueron@amazon.com)

This library is licensed under the Apache 2.0 License. 

To compile:
    make

Compilation flags:
- CC                   - To set the compiler
- AS                   - To set the assembly version
- PERF                 - To measure performance
- COUNT_INSTRUCTIONS   - To measure the number of instructions (set PERF=1)
- VAES                 - To use vector AES_NI instructions on Intel ICL platforms

Compilation example:

make CC=clang-6.0 AS=binutils-2.30/gas/as-new PERF=1 COUNT_INSTRUCTIONS=1 VAES=1

In order to run the DRBG with the new VAES instructions:

1) Prerequisites:

     1.1) Download Software Developer Emulator (SDE) version 8.12 or higher, 
       from https://software.intel.com/en-us/articles/intel-software-development-emulator

     1.2) Ensure the assembly version (binutils) is 2.30 or higher.

     1.3) Use at least gcc 8.2.0 or clang 6.0. older compilers will not recognize the -mvaes flag.

2) Run the binary using SDE

     2.1) sde -icl -mix -start_ssc_mark 1 -stop_ssc_mark 2 -- ./bin/ctr_drbg 

If the COUNT_INSTRUCTIONS flag is set, the results will appear in sde-mix-out.txt. 
See the SDE site above on instructions on how to read this file.

[1] Drucker, Nir, Shay Gueron, and Vlad Krasnov. 2018. 
Making AES Great Again: The Forthcoming Vectorized AES Instruction.
IACR Cryptology EPrint Archive. https://eprint.iacr.org/2018/392.pdf

[2] Intel architecture instruction set extensions programming reference.
https://software.intel.com/sites/default/files/managed/c5/15/architecture-instruction-set-extensions-programming-reference.pdf
, October 2017.
