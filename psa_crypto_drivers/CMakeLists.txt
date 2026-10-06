# Copyright (c) 2026 ITE Corporation. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if(DEFINED ZEPHYR_BASE)
	# Zephyr build
	zephyr_include_directories(configs)
	add_subdirectory(psa_transparent_drivers/zephyr)
else()
	# Non-Zephyr build
endif(DEFINED ZEPHYR_BASE)
