/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "it51xxx_crypto_core.h"

#include <zephyr/kernel.h>

Z_GENERIC_SECTION(.__hwcrypto_dlm_block) union hwcrypto_dlm_block hwcrypto_dlm;

mm_reg_t it51xxx_hwcrypto_get_base(void)
{
	return 0xf03b00; /* TODO */
}

/**
 * @brief Implementation of mutex_init for thread-safety.
 *
 */
int it51xxx_hwcrypto_mutex_init(struct k_mutex *mutex)
{
	return k_mutex_init(mutex);
}

/**
 * @brief Implementation of mutex_lock for thread-safety.
 *
 * @return 0 if successful, -1 if not
 */

int it51xxx_hwcrypto_mutex_lock(struct k_mutex *mutex, k_timeout_t timeout)
{
	return k_mutex_lock(mutex, timeout);
}

/**
 * @brief Implementation of mutex_unlock for thread-safety.
 *
 * @return 0 if successful, -1 if not
 */
int it51xxx_hwcrypto_mutex_unlock(struct k_mutex *mutex)
{
	return k_mutex_unlock(mutex);
}
