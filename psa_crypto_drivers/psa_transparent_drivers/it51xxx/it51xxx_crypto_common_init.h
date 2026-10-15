/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IT51XXX_CRYPTO_COMMON_INIT_H
#define IT51XXX_CRYPTO_COMMON_INIT_H

/** \file it51xxx_crypto_common_init.h
 *
 * TODO
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

extern struct k_mutex *it51xxx_hwcrypto_mutex;

psa_status_t it51xxx_hwcrypto_common_init(void);
psa_status_t it51xxx_hwcrypto_common_free(void);

#ifdef __cplusplus
}
#endif
#endif /* IT51XXX_CRYPTO_COMMON_INIT_H */
