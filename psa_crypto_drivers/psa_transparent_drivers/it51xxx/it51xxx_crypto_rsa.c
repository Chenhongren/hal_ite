/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "ite_psa_mbedtls_origin.h"
#include "it51xxx_crypto_common_init.h"
#include "it51xxx_crypto_core.h"
#include "it51xxx_crypto_rsa.h"

#include "psa_crypto_rsa.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_core.h"
#include "mbedtls/platform.h"
#include "mbedtls/private/bignum.h"
#include "mbedtls/oid.h"

#include <zephyr/logging/log.h>
// LOG_MODULE_REGISTER(it51xxx_crypto_rsa, CONFIG_LOG_DEFAULT_LEVEL);
LOG_MODULE_REGISTER(it51xxx_crypto_rsa, LOG_LEVEL_DBG);

#define rsa_dlm (hwcrypto_dlm.rsa)

#define RSA40_CTRL             0x40
#define RSA_ENABLE             BIT(7)
#define RSA_EXPONENT_MASK      GENMASK(5, 4)
#define RSA_EXPONENT_SELECT(n) FIELD_PREP(GENMASK(5, 4), n)
#define RSA_INTERRUPT_ENABLE   BIT(1)
#define RSA_CLOCK_ENABLE       BIT(0)

#define RSA41_CTRL_2                      0x41
#define RSA_PUBLIC_MODULUS_LENGTH_DIVISOR 32U
#define PUBLIC_MODULUS_LENGTH(n)          (n / RSA_PUBLIC_MODULUS_LENGTH_DIVISOR)

#define RSA42_STATUS          0x42
#define RSA_CALCULATION_START BIT(7)
#define RSA_CALCULATION_DONE  BIT(1)

#define RSA44_BASE_ADDR_BYTE_1 0x44
#define RSA_BASE_ADDR_LB(n)    FIELD_PREP(GENMASK(7, 4), n)

#define RSA45_BASE_ADDR_BYTE_2 0x45
#define RSA_BASE_ADDR_HB(n)    FIELD_PREP(GENMASK(1, 0), n)

static const uint32_t it51xxx_rsa_supported_exponents[] = {3U, 65537U};

enum it51xxx_rsa_key_select {
	KEY_PUBLIC_EXP_65537 = 0,
	KEY_PUBLIC_EXP_3,
	KEY_PRIVATE,
	KEY_RESERVED,
};

struct {
	uint8_t public[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
	uint8_t private[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
	size_t size;
} keys;

static inline int it51xxx_crypto_rsa_exp_valid(const mbedtls_rsa_context *rsa)
{
	uint8_t exponent[4];
	int ret;

	for (size_t i = 0; i < ARRAY_SIZE(it51xxx_rsa_supported_exponents); i++) {
		if (mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(E),
					it51xxx_rsa_supported_exponents[i]) == 0) {
			return 0;
		}
	}

	ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(E), exponent, sizeof(exponent));
	if (ret) {
		LOG_ERR("failed to export exponent (%zu bits), %d",
			mbedtls_mpi_bitlen(&rsa->MBEDTLS_PRIVATE(E)), ret);
	} else {
		LOG_HEXDUMP_ERR(exponent, sizeof(exponent), "unsupported exponent:");
	}

	return PSA_ERROR_NOT_SUPPORTED;
}

static inline int it51xxx_crypto_rsa_add_pkcs1_v15_padding(const mbedtls_rsa_context *rsa,
							   unsigned int hashlen,
							   const uint8_t *hash, uint8_t *encode)
{
	size_t sig_len = mbedtls_rsa_get_len(rsa);
	int ret = rsa_rsassa_pkcs1_v15_encode(mbedtls_rsa_get_md_alg(rsa), hashlen, hash, sig_len,
					      encode);

	if (ret) {
		return ret;
	}

	LOG_HEXDUMP_DBG(encode, sig_len, "padding data:");

	return 0;
}

static int it51xxx_set_rsa_keys(mbedtls_rsa_context *rsa)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();
	int ret;

	ret = it51xxx_crypto_rsa_exp_valid(rsa);
	if (ret) {
		return ret;
	}

	keys.size = mbedtls_rsa_get_len(rsa);
	ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(N), (unsigned char *)keys.public,
				       keys.size);
	if (ret) {
		return ret;
	}

	ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(D), (unsigned char *)keys.private,
				       keys.size);
	if (ret) {
		return ret;
	}

	memset(rsa_dlm.key_private, 0, sizeof(rsa_dlm.key_private));
	memset(rsa_dlm.key_public, 0, sizeof(rsa_dlm.key_public));

	for (size_t i = 0; i < keys.size; i++) {
		rsa_dlm.key_private[i] = keys.private[keys.size - i - 1];
	}

	for (size_t i = 0; i < keys.size; i++) {
		rsa_dlm.key_public[i] = keys.public[keys.size - i - 1];
	}

	sys_write8(PUBLIC_MODULUS_LENGTH(keys.size * BITS_PER_BYTE), base + RSA41_CTRL_2);

	return 0;
}

static int it51xxx_start_rsa_calculation(void)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();

	sys_write8(RSA_CALCULATION_START, base + RSA42_STATUS);

	/* wait for completion */
#if 0 /* TODO */
	k_sem_take(&data->rsa_cal_done, K_FOREVER);
#else
	while ((sys_read8(base + RSA42_STATUS) & RSA_CALCULATION_DONE) != RSA_CALCULATION_DONE)
		;
	sys_write8(sys_read8(base + RSA42_STATUS) | RSA_CALCULATION_DONE, base + RSA42_STATUS);
#endif

	sys_write8(sys_read8(base + RSA40_CTRL) & ~(RSA_ENABLE | RSA_CLOCK_ENABLE),
		   base + RSA40_CTRL);

	return 0;
}

static int it51xxx_crypto_rsa_sign(mbedtls_md_type_t md_alg, mbedtls_rsa_context *rsa,
				   unsigned int hashlen, const uint8_t *hash, unsigned char *sig)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();
	int ret;
	size_t sig_len = mbedtls_rsa_get_len(rsa);
	uint8_t rsa_ctrl_val;
	uint8_t hash_with_padding[sig_len];

	ret = it51xxx_set_rsa_keys(rsa);
	if (ret) {
		return ret;
	}

	ret = it51xxx_crypto_rsa_add_pkcs1_v15_padding(rsa, hashlen, hash, hash_with_padding);
	if (ret) {
		return ret;
	}

	memset(rsa_dlm.messages, 0, sizeof(rsa_dlm.messages));
	for (size_t i = 0; i < sig_len; i++) {
		rsa_dlm.messages[i] = hash_with_padding[sig_len - i - 1];
	}

	rsa_ctrl_val = sys_read8(base + RSA40_CTRL) & ~RSA_EXPONENT_MASK;
	rsa_ctrl_val |= RSA_ENABLE | RSA_CLOCK_ENABLE | RSA_EXPONENT_SELECT(KEY_PRIVATE);
	sys_write8(rsa_ctrl_val, base + RSA40_CTRL);

	ret = it51xxx_start_rsa_calculation();
	if (ret) {
		return ret;
	}

	for (size_t i = 0; i < sig_len; i++) {
		sig[sig_len - i - 1] = rsa_dlm.messages[i];
	}

	LOG_HEXDUMP_DBG(sig, sig_len, "sign:");

	return ret;
}

static int it51xxx_crypto_rsa_verify(mbedtls_rsa_context *rsa, unsigned int hashlen,
				     const uint8_t *hash, const unsigned char *sig)
{
	bool exponent_3 = !mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(E), 3);
	const mm_reg_t base = it51xxx_hwcrypto_get_base();
	int ret;
	size_t sig_len = mbedtls_rsa_get_len(rsa);
	uint8_t rsa_ctrl_val;
	uint8_t encoded[sig_len];
	uint8_t encoded_expected[sig_len];

	ret = it51xxx_set_rsa_keys(rsa);
	if (ret) {
		return ret;
	}

	ret = it51xxx_crypto_rsa_add_pkcs1_v15_padding(rsa, hashlen, hash, encoded_expected);
	if (ret) {
		return ret;
	}

	memset(rsa_dlm.messages, 0, sizeof(rsa_dlm.messages));
	for (size_t i = 0; i < sig_len; i++) {
		rsa_dlm.messages[i] = sig[sig_len - i - 1];
	}

	rsa_ctrl_val = sys_read8(base + RSA40_CTRL) & ~RSA_EXPONENT_MASK;
	rsa_ctrl_val |= RSA_ENABLE | RSA_CLOCK_ENABLE;
	rsa_ctrl_val |= exponent_3 ? RSA_EXPONENT_SELECT(KEY_PUBLIC_EXP_3)
				   : RSA_EXPONENT_SELECT(KEY_PUBLIC_EXP_65537);
	sys_write8(rsa_ctrl_val, base + RSA40_CTRL);

	ret = it51xxx_start_rsa_calculation();
	if (ret) {
		return ret;
	}

	for (size_t i = 0; i < sig_len; i++) {
		encoded[sig_len - i - 1] = rsa_dlm.messages[i];
	}

	LOG_HEXDUMP_DBG(encoded, sig_len, "verify:");

	if (memcmp(encoded, encoded_expected, sig_len)) {
		return PSA_ERROR_INVALID_SIGNATURE;
	}

	return PSA_SUCCESS;
}

static psa_status_t it51xxx_psa_rsa_sign_hash(const psa_key_attributes_t *attributes,
					      const uint8_t *key_buffer, size_t key_buffer_size,
					      psa_algorithm_t alg, const uint8_t *hash,
					      size_t hash_length, uint8_t *signature,
					      size_t signature_size, size_t *signature_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	int ret = PSA_ERROR_CORRUPTION_DETECTED;
	mbedtls_rsa_context *rsa = NULL;
	mbedtls_md_type_t md_alg;

	status = mbedtls_psa_rsa_load_representation(psa_get_key_type(attributes), key_buffer,
						     key_buffer_size, &rsa);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	status = psa_rsa_decode_md_type(alg, hash_length, &md_alg);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	if (signature_size < mbedtls_rsa_get_len(rsa)) {
		status = PSA_ERROR_BUFFER_TOO_SMALL;
		goto exit;
	}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
		ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
		if (ret == 0) {
			(void)it51xxx_hwcrypto_mutex_lock(it51xxx_hwcrypto_mutex, K_FOREVER);
			ret = it51xxx_crypto_rsa_sign(md_alg, rsa, (unsigned int)hash_length, hash,
						      signature);
			it51xxx_hwcrypto_mutex_unlock(it51xxx_hwcrypto_mutex);
		}
	} else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
	{
		status = PSA_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (ret == 0) {
		*signature_length = mbedtls_rsa_get_len(rsa);
	}
	status = mbedtls_to_psa_error(ret);

exit:
	mbedtls_rsa_free(rsa);
	mbedtls_free(rsa);

	return status;
}

static psa_status_t it51xxx_psa_rsa_verify_hash(const psa_key_attributes_t *attributes,
						const uint8_t *key_buffer, size_t key_buffer_size,
						psa_algorithm_t alg, const uint8_t *hash,
						size_t hash_length, const uint8_t *signature,
						size_t signature_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	int ret;
	mbedtls_rsa_context *rsa = NULL;
	mbedtls_md_type_t md_alg;

	status = mbedtls_psa_rsa_load_representation(psa_get_key_type(attributes), key_buffer,
						     key_buffer_size, &rsa);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	status = psa_rsa_decode_md_type(alg, hash_length, &md_alg);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	if (signature_length != mbedtls_rsa_get_len(rsa)) {
		status = PSA_ERROR_INVALID_SIGNATURE;
		goto exit;
	}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
		ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
		if (ret == 0) {
			(void)it51xxx_hwcrypto_mutex_lock(it51xxx_hwcrypto_mutex, K_FOREVER);
			ret = it51xxx_crypto_rsa_verify(rsa, (unsigned int)hash_length, hash,
							signature);
			it51xxx_hwcrypto_mutex_unlock(it51xxx_hwcrypto_mutex);
		}
	} else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
	{
		status = PSA_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	/* Mbed TLS distinguishes "invalid padding" from "valid padding but
	 * the rest of the signature is invalid". This has little use in
	 * practice and PSA doesn't report this distinction. */
	status = (ret == MBEDTLS_ERR_RSA_INVALID_PADDING) ? PSA_ERROR_INVALID_SIGNATURE
							  : mbedtls_to_psa_error(ret);

exit:
	mbedtls_rsa_free(rsa);
	mbedtls_free(rsa);

	return status;
}

psa_status_t ite_it51xxx_transparent_sign_hash(const psa_key_attributes_t *attributes,
					       const uint8_t *key_buffer, size_t key_buffer_size,
					       psa_algorithm_t alg, const uint8_t *hash,
					       size_t hash_length, uint8_t *signature,
					       size_t signature_size, size_t *signature_length)
{
	if (psa_get_key_type(attributes) == PSA_KEY_TYPE_RSA_KEY_PAIR) {
		if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
			return it51xxx_psa_rsa_sign_hash(attributes, key_buffer, key_buffer_size,
							 alg, hash, hash_length, signature,
							 signature_size, signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) */
		} else {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	(void)key_buffer;
	(void)key_buffer_size;
	(void)hash;
	(void)hash_length;
	(void)signature;
	(void)signature_size;
	(void)signature_length;

	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t ite_it51xxx_transparent_verify_hash(const psa_key_attributes_t *attributes,
						 const uint8_t *key_buffer, size_t key_buffer_size,
						 psa_algorithm_t alg, const uint8_t *hash,
						 size_t hash_length, const uint8_t *signature,
						 size_t signature_length)
{

	if (PSA_KEY_TYPE_IS_RSA(psa_get_key_type(attributes))) {
		if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
			return it51xxx_psa_rsa_verify_hash(attributes, key_buffer, key_buffer_size,
							   alg, hash, hash_length, signature,
							   signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) */
		} else {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	(void)key_buffer;
	(void)key_buffer_size;
	(void)hash;
	(void)hash_length;
	(void)signature;
	(void)signature_length;

	return PSA_ERROR_NOT_SUPPORTED;
}
