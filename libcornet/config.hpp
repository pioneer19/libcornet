/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once
// auto generated file from config.hpp.in

#define USE_IO_URING  true
#define SNI_HOSTNAME  "localhost"

namespace pioneer19::cornet::config
{
    inline constexpr char  io_mode[]     = "io_uring";
    inline constexpr bool  use_common_io = false;
    inline constexpr bool  use_io_uring  = true;
}
