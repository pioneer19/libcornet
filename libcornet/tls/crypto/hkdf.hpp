/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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
