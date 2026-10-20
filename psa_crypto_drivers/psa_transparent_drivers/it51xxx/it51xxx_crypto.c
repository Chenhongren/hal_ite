/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "it51xxx_crypto.h"
#if PSA_CRYPTO_DRIVER_ITE_IT51XXX_RSA
#include "it51xxx_crypto_rsa.h"
#endif /* PSA_CRYPTO_DRIVER_ITE_IT51XXX_RSA */
#if PSA_CRYPTO_DRIVER_ITE_IT51XXX_SHA
#include "it51xxx_crypto_sha.h"
#endif /* PSA_CRYPTO_DRIVER_ITE_IT51XXX_SHA */

#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>

#define DT_DRV_COMPAT ite_it51xxx_crypto

Z_GENERIC_SECTION(.__hwcrypto_dlm_block) union hwcrypto_dlm_block hwcrypto_dlm;

BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(DT_DRV_COMPAT) == 1,
	     "it51xxx: supported one crypto controller only");

struct k_mutex it51xxx_hwcrypto_mutex;

mm_reg_t it51xxx_hwcrypto_get_base(void)
{
	return (mm_reg_t)DT_REG_ADDR(DT_COMPAT_GET_ANY_STATUS_OKAY(DT_DRV_COMPAT));
}

psa_status_t it51xxx_hwcrypto_mutex_lock(k_timeout_t timeout)
{
	if (k_mutex_lock(&it51xxx_hwcrypto_mutex, timeout)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	return PSA_SUCCESS;
}

psa_status_t it51xxx_hwcrypto_mutex_unlock(void)
{
	if (k_mutex_unlock(&it51xxx_hwcrypto_mutex)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	return PSA_SUCCESS;
}

psa_status_t it51xxx_hwcrypto_init(void)
{
	if (k_mutex_init(&it51xxx_hwcrypto_mutex)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

#if PSA_CRYPTO_DRIVER_ITE_IT51XXX_RSA
	it51xxx_crypto_rsa_init();
#endif /* PSA_CRYPTO_DRIVER_ITE_IT51XXX_RSA */

#if PSA_CRYPTO_DRIVER_ITE_IT51XXX_SHA
	it51xxx_crypto_sha_init();
#endif /* PSA_CRYPTO_DRIVER_ITE_IT51XXX_SHA */

	return PSA_SUCCESS;
}

psa_status_t it51xxx_hwcrypto_free(void)
{
	return PSA_SUCCESS;
}
