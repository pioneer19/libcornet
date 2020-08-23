/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once
// auto generated from version.hpp.in

// The numeric version format is AAABBBCCCDDDE where:
//
// AAA - major version number
// BBB - minor version number
// CCC - bugfix version number
// DDD - alpha / beta (DDD + 500) version number
// E   - final (0) / snapshot (1)
//
// When DDDE is not 0, 1 is subtracted from AAABBBCCC. For example:
//
// Version      AAABBBCCCDDDE
//
// 0.1.0        0000010000000
// 0.1.2        0000010010000
// 1.2.3        0010020030000
// 2.2.0-a.1    0020019990010
// 3.0.0-b.2    0029999995020
// 2.2.0-a.1.z  0020019990011
//
#define LIBCORNET_VERSION       999990001ULL
#define LIBCORNET_VERSION_STR   "0.1.0-a.0.20200509132228"
#define LIBCORNET_VERSION_ID    "0.1.0-a.0.20200509132228"

#define LIBCORNET_VERSION_MAJOR 0
#define LIBCORNET_VERSION_MINOR 1
#define LIBCORNET_VERSION_PATCH 0

#define LIBCORNET_PRE_RELEASE   true

#define LIBCORNET_SNAPSHOT_SN   20200509132228ULL
#define LIBCORNET_SNAPSHOT_ID   ""
