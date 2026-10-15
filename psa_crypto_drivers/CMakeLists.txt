# Copyright (c) 2026 ITE Corporation. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(configs)

if(CONFIG_PSA_CRYPTO_DRIVER_ITE_IT51XXXX)
	message ("The it51xxx-psa-crypto-driver module is included")

	set(MBEDTLS_PATH ${ZEPHYR_BASE}/../modules/crypto/mbedtls)
	set(TF_PSA_CRYPTO_PATH ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto)
	set(IT51XXX_PSA_TRANSPARENT_DRIVER_PATH ${CMAKE_CURRENT_LIST_DIR}/psa_transparent_drivers/it51xxx)

	zephyr_compile_definitions(
		PSA_CRYPTO_DRIVER_ITE_IT51XXXX
	)

	# MbedTLS and TF-PSA-CRYPTO
	zephyr_library_include_directories(
		${MBEDTLS_PATH}/include
		${MBEDTLS_PATH}/include/mbedtls
		${TF_PSA_CRYPTO_PATH}/core
		${TF_PSA_CRYPTO_PATH}/drivers/builtin/src
		${TF_PSA_CRYPTO_PATH}/drivers/builtin/include/mbedtls/private
	)

	# PSA Transparent Drivers
	## Include paths
	zephyr_include_directories(
		${IT51XXX_PSA_TRANSPARENT_DRIVER_PATH}/
		${IT51XXX_PSA_TRANSPARENT_DRIVER_PATH}/common
	)
	## Sources
	zephyr_sources(
		${IT51XXX_PSA_TRANSPARENT_DRIVER_PATH}/it51xxx_crypto_rsa.c
		${IT51XXX_PSA_TRANSPARENT_DRIVER_PATH}/it51xxx_crypto_core.c
		${IT51XXX_PSA_TRANSPARENT_DRIVER_PATH}/common/ite_psa_mbedtls_origin.c
	)

endif() # CONFIG_PSA_CRYPTO_DRIVER_ITE_IT51XXXX
