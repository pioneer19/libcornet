/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/crypto.hpp>

#include <stdexcept>

#include <openssl/rand.h>
#include <openssl/err.h>

namespace pioneer19::cornet::crypto
{

void random_bytes( uint8_t* buff, uint32_t size )
{
    int res = RAND_bytes( buff, size );
    if( res != 1 )
        throw std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );
}

}
