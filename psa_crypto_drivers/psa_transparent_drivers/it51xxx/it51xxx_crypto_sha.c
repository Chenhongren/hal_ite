/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "ite_psa_mbedtls_origin.h"
#include "it51xxx_crypto.h"
#include "it51xxx_crypto_sha.h"

#include "psa_crypto_core.h"

#include <soc_common.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#define LOG_LEVEL CONFIG_PSA_CRYPTO_IT51XXX_LOG_LEVEL
LOG_MODULE_REGISTER(it51xxx_psa_crypto_sha);

#define DT_DRV_COMPAT    ite_it51xxx_psa_sha
#define IT51XXX_SHA_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(DT_DRV_COMPAT)
BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(DT_DRV_COMPAT) == 1,
	     "it51xxx: supported one crypto-sha node only");

#define IT51XXX_SHA_IRQ DT_IRQN(DT_PARENT(IT51XXX_SHA_NODE))

#define SHA00_CTRL       0x00
#define SHA_WRITE_BACK   BIT(2)
#define SHA_INIT         BIT(1)
#define SHA_LOAD_AND_EXE BIT(0)

#define SHA01_STATUS 0x01
#define INT_ENABLE   BIT(3)
#define INT_STATUS   BIT(2)
#define SHA_BUSY     BIT(0)

#define SHA02_EXECUTION_COUNTER      0x02
#define SHA224_SHA256_EXE_ONCE_BYTES 64
#define SHA384_SHA512_EXE_ONCE_BYTES 128

#define SHA03_BASE_ADDR_0 0x03
#define BASE_ADDR_0_MASK  GENMASK(7, 6)
#define BASE_ADDR_0(x)    ((uint8_t)((x) & BASE_ADDR_0_MASK))

#define SHA04_BASE_ADDR_1 0x04
#define BASE_ADDR_1(x)    ((uint8_t)FIELD_GET(GENMASK(15, 8), (x)))

#define SHA05_SETTING    0x05
#define SELECT_SHA2_MASK GENMASK(2, 1)
#define SELECT_SHA2(x)   FIELD_PREP(SELECT_SHA2_MASK, x)
#define SHA1_FAMILY      BIT(0)

#define SHA06_BASE_ADDR_2 0x06
#define BASE_ADDR_2(x)    ((uint8_t)FIELD_GET(GENMASK(17, 16), (x)))

#define SHA_SHA256_BLOCK_LEN 64 /* TODO */

#define IT51XXX_SHA_INIT 1U

#define sha_dlm hwcrypto_dlm.sha

enum it51xxx_sha2_algorithm {
	IT51XXX_SHA2_SHA256 = 0,
	IT51XXX_SHA2_SHA512,
	IT51XXX_SHA2_SHA224,
	IT51XXX_SHA2_SHA384,
};

enum it51xxx_sha256_execute_bytes {
	IT51XXX_SHA256_EXE_64_BYTE = 64,
	IT51XXX_SHA256_EXE_512_BYTE = 512,
	IT51XXX_SHA256_EXE_1024_BYTE = 1024,
};

static const uint8_t sha224_sha256_supported_execute_times[] = {1U, 8U, 16U};
static const uint8_t sha384_sha512_supported_execute_times[] = {1U, 4U, 8U};

struct k_sem sha_cal_done;

static void it51xxx_sha_isr(const void *arg)
{
	ARG_UNUSED(arg);

	const mm_reg_t base = it51xxx_hwcrypto_get_base();
	uint8_t sha_sts = sys_read8(base + SHA01_STATUS);

	if (sha_sts & INT_STATUS) {
		k_sem_give(&sha_cal_done);
		sys_write8(sha_sts | INT_STATUS, base + SHA01_STATUS);
	}
}

static int it51xxx_sha_set_algorithm(psa_algorithm_t alg)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();

	switch (alg) {
	case PSA_ALG_SHA_256:
		sys_write8(SELECT_SHA2(IT51XXX_SHA2_SHA256), base + SHA05_SETTING);
		break;
	case PSA_ALG_SHA_224:
		__fallthrough;
	case PSA_ALG_SHA_384:
		__fallthrough;
	case PSA_ALG_SHA_512:
		__fallthrough;
	default:
		return -ENOTSUP;
	}

	return 0;
}

static void it51xxx_sha256_init(void)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();

	sha_dlm.sha_init = IT51XXX_SHA_INIT;
	sha_dlm.total_len = 0;
	sha_dlm.input_bytes_index = 0;

	sys_write8(BASE_ADDR_0((uintptr_t)&sha_dlm), base + SHA03_BASE_ADDR_0);
	sys_write8(BASE_ADDR_1((uintptr_t)&sha_dlm), base + SHA04_BASE_ADDR_1);
	sys_write8(BASE_ADDR_2((uintptr_t)&sha_dlm), base + SHA06_BASE_ADDR_2);
}

/* TODO: check return code */
static int it51xxx_sha256_module_calculation(const uint16_t calculation_bytes)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();
	uint8_t reg_val;

	for (size_t i = 0; i <= ARRAY_SIZE(sha224_sha256_supported_execute_times); i++) {
		if (i == ARRAY_SIZE(sha224_sha256_supported_execute_times)) {
			return -ENOTSUP;
		}

		if (calculation_bytes ==
		    SHA224_SHA256_EXE_ONCE_BYTES * sha224_sha256_supported_execute_times[i]) {
			reg_val = sha224_sha256_supported_execute_times[i] - 1;
			break;
		}
	}

	/* load data from dlm */
	sys_write8(reg_val, base + SHA02_EXECUTION_COUNTER);
	while (sys_read8(base + SHA01_STATUS) & SHA_BUSY)
		;

	reg_val = 0;

	if (sha_dlm.sha_init) {
		sha_dlm.sha_init = 0;
		reg_val |= SHA_INIT;
	}
	sys_write8(reg_val | SHA_LOAD_AND_EXE, base + SHA00_CTRL);
	k_sem_take(&sha_cal_done, K_FOREVER);

	sha_dlm.input_bytes_index = 0;

	return 0;
}

static void it51xxx_write_back_hash_result(uint8_t *hash, size_t *hash_length)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();

	sys_write8(BASE_ADDR_0((uintptr_t)&sha_dlm.hash), base + SHA03_BASE_ADDR_0);
	sys_write8(BASE_ADDR_1((uintptr_t)&sha_dlm.hash), base + SHA04_BASE_ADDR_1);
	sys_write8(BASE_ADDR_2((uintptr_t)&sha_dlm.hash), base + SHA06_BASE_ADDR_2);

	/* write back the hash result to dlm */
	sys_write8(SHA_WRITE_BACK, base + SHA00_CTRL);
	k_sem_take(&sha_cal_done, K_FOREVER);

	memcpy(hash, sha_dlm.hash, sizeof(sha_dlm.hash));
	*hash_length = sizeof(sha_dlm.hash);
}

static void it51xxx_sha_calculate_hash(const uint8_t *input, size_t input_length, uint8_t *hash,
				       size_t *hash_length)
{
	uint32_t in_buf_idx = 0;
	uint32_t rem_len = input_length;

	it51xxx_sha256_init();

	/* data length >= 1k bytes */
	while (rem_len >= IT51XXX_SHA256_EXE_1024_BYTE) {
		rem_len -= IT51XXX_SHA256_EXE_1024_BYTE;

		memcpy(sha_dlm.input_bytes + sha_dlm.input_bytes_index, input + in_buf_idx,
		       IT51XXX_SHA256_EXE_1024_BYTE);

		sha_dlm.input_bytes_index += IT51XXX_SHA256_EXE_1024_BYTE;
		in_buf_idx += IT51XXX_SHA256_EXE_1024_BYTE;

		it51xxx_sha256_module_calculation(IT51XXX_SHA256_EXE_1024_BYTE);
	}

	/* data length >= 512 bytes */
	while (rem_len >= IT51XXX_SHA256_EXE_512_BYTE) {
		rem_len -= IT51XXX_SHA256_EXE_512_BYTE;

		memcpy(sha_dlm.input_bytes + sha_dlm.input_bytes_index, input + in_buf_idx,
		       IT51XXX_SHA256_EXE_512_BYTE);

		sha_dlm.input_bytes_index += IT51XXX_SHA256_EXE_512_BYTE;
		in_buf_idx += IT51XXX_SHA256_EXE_512_BYTE;

		it51xxx_sha256_module_calculation(IT51XXX_SHA256_EXE_512_BYTE);
	}

	/* 0 <= data length < 512 bytes */
	while (rem_len) {
		rem_len--;
		sha_dlm.input_bytes[sha_dlm.input_bytes_index++] = input[in_buf_idx++];

		/*
		 * If fill full 64 bytes then execute HW calculation.
		 * If not, will execute in later finish block.
		 */
		if (sha_dlm.input_bytes_index >= SHA_SHA256_BLOCK_LEN) {
			it51xxx_sha256_module_calculation(IT51XXX_SHA256_EXE_64_BYTE);
		}
	}

	sha_dlm.total_len = input_length;

	/* append the padding bit (0x80), then zero-fill the rest of the block. */
	sha_dlm.input_bytes[sha_dlm.input_bytes_index++] = 0x80;
	memset(&sha_dlm.input_bytes[sha_dlm.input_bytes_index], 0,
	       SHA_SHA256_BLOCK_LEN - sha_dlm.input_bytes_index);

	/* Reserve the last eight bytes for the message length in bits.
	 * If fewer than eight bytes remain after appending the padding
	 * bit, process this block and zero-fill new block for the length
	 * field.
	 */
	if (sha_dlm.input_bytes_index > 56) {
		it51xxx_sha256_module_calculation(IT51XXX_SHA256_EXE_64_BYTE);

		memset(&sha_dlm.input_bytes[sha_dlm.input_bytes_index], 0,
		       SHA_SHA256_BLOCK_LEN - sha_dlm.input_bytes_index);
	}

	/* Store the low 32 bits of the message length in bits in big-endian
	 * byte order, converting from the CPU's little-endian representation.
	 */
	sha_dlm.input_words[15] = sys_cpu_to_be32(sha_dlm.total_len * 8);

	it51xxx_sha256_module_calculation(IT51XXX_SHA256_EXE_64_BYTE);

	it51xxx_write_back_hash_result(hash, hash_length);
}

psa_status_t ite_it51xxx_transparent_hash_compute(psa_algorithm_t alg, const uint8_t *input,
						  size_t input_length, uint8_t *hash,
						  size_t hash_size, size_t *hash_length)
{
	size_t actual_hash_length = PSA_HASH_LENGTH(alg);

	if (!hash || !hash_size) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	/* Fill the output buffer with something that isn't a valid hash
	 * (barring an attack on the hash and deliberately-crafted input),
	 * in case the caller doesn't check the return status properly. */

	/* If hash_size is 0 then hash may be NULL and then the
	 * call to memset would have undefined behavior. */
	if (hash_size != 0) {
		memset(hash, '!', hash_size);
	}

	if (hash_size < actual_hash_length) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	if (input_length > UINT32_MAX / 8U) {
		LOG_ERR("input length is too large: %zu/%zu bytes", input_length,
			(size_t)(UINT32_MAX / 8U));
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	(void)it51xxx_hwcrypto_mutex_lock(K_FOREVER);

	*hash_length = 0;
	if (it51xxx_sha_set_algorithm(alg)) {
		it51xxx_hwcrypto_mutex_unlock();
		return PSA_ERROR_NOT_SUPPORTED;
	}

	chip_block_idle();
	it51xxx_sha_calculate_hash(input, input_length, hash, hash_length);
	chip_permit_idle();

	LOG_HEXDUMP_DBG(hash, *hash_length, "hash:");

	it51xxx_hwcrypto_mutex_unlock();

	return PSA_SUCCESS;
}

void it51xxx_crypto_sha_init(void)
{
	const mm_reg_t base = it51xxx_hwcrypto_get_base();

	k_sem_init(&sha_cal_done, 0, 1);

	/* enable sha interrupt */
	sys_write8(sys_read8(base + SHA01_STATUS) | INT_ENABLE, base + SHA01_STATUS);

	IRQ_CONNECT(IT51XXX_SHA_IRQ, 0, it51xxx_sha_isr, NULL, 0);
	irq_enable(IT51XXX_SHA_IRQ);
}
