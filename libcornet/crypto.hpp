/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <cstdint>

namespace pioneer19::cornet::crypto
{

void   random_bytes( uint8_t* buff, uint32_t size );

}
