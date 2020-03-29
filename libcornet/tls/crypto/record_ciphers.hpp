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

#include <cstdint>
#include <memory>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <libcornet/tls/types.hpp>

namespace pioneer19::cornet::tls13::crypto
{

class TlsCipherSuite
{
public:
    TlsCipherSuite()  noexcept;
    ~TlsCipherSuite() noexcept;

    TlsCipherSuite( TlsCipherSuite&& ) noexcept;
    TlsCipherSuite& operator=( TlsCipherSuite&& ) noexcept;

    TlsCipherSuite( const TlsCipherSuite& )       = delete;
    TlsCipherSuite& operator=( const TlsCipherSuite& ) = delete;

    static bool is_supported_cipher_suite( record::CipherSuite cipher_suite );
    void set_cipher_suite( record::CipherSuite cipher_suite );

    uint32_t encrypt( const uint8_t* plaintext, uint32_t plaintext_size
            ,const uint8_t* aad, uint32_t aad_size
            ,uint8_t* ciphertext, uint8_t* tag ) noexcept;
    uint32_t encrypt2( const uint8_t* plaintext, uint32_t plaintext_size
            ,const uint8_t* plaintext_tail, uint32_t tail_size
            ,const uint8_t* aad, uint32_t aad_size
            ,uint8_t* ciphertext, uint8_t* tag ) noexcept;
    uint32_t decrypt( const uint8_t* ciphertext, uint32_t ciphertext_size
            ,const uint8_t* aad, uint32_t aad_size, const uint8_t* tag
            ,uint8_t* plaintext) noexcept;
    void reset_key_counters() noexcept { m_sender_counter = 0; m_receiver_counter = 0; }
    [[nodiscard]]
    uint8_t* sender_key_data() noexcept { return m_sender_key; }
    [[nodiscard]]
    uint8_t* receiver_key_data() noexcept { return m_receiver_key; }
    [[nodiscard]]
    uint32_t key_size() const noexcept { return m_key_size; }
    [[nodiscard]]
    uint8_t* sender_iv_data() noexcept { return m_sender_iv; }
    [[nodiscard]]
    uint8_t* receiver_iv_data() noexcept { return m_receiver_iv; }
    [[nodiscard]]
    static uint32_t iv_size()  noexcept { return 12; }
    [[nodiscard]]
    static uint32_t tag_size() noexcept { return 16; }
    [[nodiscard]]
    const EVP_MD* digest() const noexcept { return m_digest; }
    [[nodiscard]]
    uint32_t digest_size() const noexcept { return m_digest_size; }

private:
    void copy_instance_data( TlsCipherSuite& other );

    EVP_CIPHER_CTX*   m_ctx    = nullptr;
    const EVP_CIPHER* m_cipher = nullptr;
    uint8_t m_sender_key  [32]; // max key size for aes128, aes256, chacha20_poly1305
    uint8_t m_sender_iv   [EVP_MAX_IV_LENGTH];
    uint8_t m_receiver_key[32];
    uint8_t m_receiver_iv [EVP_MAX_IV_LENGTH];
    uint64_t m_sender_counter   = 0;
    uint64_t m_receiver_counter = 0;
    const EVP_MD* m_digest = nullptr;
    uint32_t m_key_size    = 0;
    uint32_t m_digest_size = 0;
};

}
