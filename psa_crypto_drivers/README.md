<!-- SPDX-License-Identifier: Apache-2.0 -->

# ITE PSA Crypto Drivers

This directory provides PSA Crypto drivers for ITE hardware accelerators and their integration with TF-PSA-Crypto.

The current implementation supports:
- RSA PKCS#1 v1.5 signing and verification using the hardware RSA accelerator

Operations that are unsupported or not yet implemented by the hardware driver fall back to software.

# Directory Structure

```text
psa_crypto_drivers/
  CMakeLists.txt                 Build rules for ITE PSA Crypto drivers
  configs/                       PSA cryptographic configuration
  dispatch/                      PSA driver dispatch wrappers and context headers
  psa_transparent_drivers/
    it51xxx/
      common/                    Mbed TLS-derived RSA support routines
      it51xxx_crypto.c           Shared hardware resource management
      it51xxx_crypto.h           Shared crypto driver definitions
      it51xxx_crypto_rsa.c       RSA driver implementation
      it51xxx_crypto_rsa.h       RSA driver entry point declarations
```
