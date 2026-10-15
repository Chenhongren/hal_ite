/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "it51xxx_crypto_common_init.h"

struct k_mutex it51xxx_hwcrypto_mutex;

psa_status_t it51xxx_hwcrypto_common_init(void)
{
	if (it51xxx_hwcrypto_mutex_init(&it51xxx_hwcrypto_mutex)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	return PSA_SUCCESS;
}

psa_status_t it51xxx_hwcrypto_common_free(void)
{
	return PSA_SUCCESS;
}
