/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IT51XXX_CRYPTO_CORE_H
#define IT51XXX_CRYPTO_CORE_H

#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

/** \file it51xxx_crypto_core.h
 *
 * TODO
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KB
#define KB(x) ((uint32_t)(x) << 10U)
#endif

#define IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN 512 /* 512 bytes (4096 bits) */
#define IT51XXX_HWCRYPTO_DLM_SIZE         KB(4)

struct it51xxx_rsa_dlm {
	uint8_t key_public[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];  /* 000h – 1FFh */
	uint8_t reserved_1[512];                                /* 200h - 3FFh */
	uint8_t messages[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];    /* 400h – 5FFh */
	uint8_t reserved_2[1024];                               /* 600h - 9FFh */
	uint8_t key_private[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN]; /* A00h – BFFh */
	uint8_t reserved_3[1024];                               /* C00h - FFFh */
};

/* The it51xxx hardware crypto engines, including SHA, RSA...etc,
 * share the same 4 KB DLM memory region. The union ensures that
 * each engine uses the same underlying memory.
 */
union hwcrypto_dlm_block {
	struct it51xxx_rsa_dlm rsa;
	uint8_t raw_data[IT51XXX_HWCRYPTO_DLM_SIZE];
};

extern union hwcrypto_dlm_block hwcrypto_dlm;

mm_reg_t it51xxx_hwcrypto_get_base(void);

int it51xxx_hwcrypto_mutex_init(struct k_mutex *mutex);
int it51xxx_hwcrypto_mutex_lock(struct k_mutex *mutex, k_timeout_t timeout);
int it51xxx_hwcrypto_mutex_unlock(struct k_mutex *mutex);

#ifdef __cplusplus
}
#endif
#endif /* IT51XXX_CRYPTO_CORE_H */
