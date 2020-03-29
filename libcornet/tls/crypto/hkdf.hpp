/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 *
 * This file is part of libcornet.
 *
 *  libcornet is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libcornet is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with libcornet.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <openssl/hmac.h>

namespace pioneer19::cornet::tls13::crypto
{

unsigned hkdf_extract( const EVP_MD* evp_md
        ,const unsigned char* salt, size_t salt_len
        ,const unsigned char* ikm, size_t  ikm_len
        ,unsigned char* prk ) noexcept;

unsigned hkdf_expand( const EVP_MD* evp_md
        ,const unsigned char* prk, size_t prk_len
        ,const unsigned char* info, size_t info_len
        ,unsigned char* okm, size_t okm_len ) noexcept;

unsigned hkdf_expand_label( const EVP_MD* evp_md
        ,const unsigned char* secret, size_t secret_size
        ,const unsigned char* label, size_t label_size
        ,const unsigned char* context, size_t context_size
        ,unsigned char* out, size_t out_size ) noexcept;

unsigned derive_secret( const EVP_MD* evp_md
        ,const unsigned char* secret, size_t secret_size
        ,const unsigned char* label, size_t label_size
        ,const unsigned char* messages, size_t messages_size
        ,unsigned char* out ) noexcept;

}
