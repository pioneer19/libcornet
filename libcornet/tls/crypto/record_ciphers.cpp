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

#include <libcornet/tls/crypto/record_ciphers.hpp>

#include <charconv>
#include <string>
#include <algorithm>
#include <stdexcept>

#include <endian.h>

#include <openssl/evp.h>

namespace pioneer19::cornet::tls13::crypto
{

static uint32_t aead_encrypt( const uint8_t* plaintext, uint32_t plaintext_size
        ,const uint8_t* aad, uint32_t aad_size
        ,const uint8_t* key, const uint8_t* iv
        ,uint8_t* ciphertext, uint8_t* tag, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx )
{
    /* Set cipher type and mode */
    EVP_EncryptInit_ex( ctx, cipher, nullptr, key, iv );
    /* Zero or more calls to specify any AAD */
    int length;
    EVP_EncryptUpdate( ctx, nullptr, &length, aad, aad_size );
    /* Encrypt plaintext */
    int ciphertext_size;
    EVP_EncryptUpdate( ctx, ciphertext, &ciphertext_size, plaintext, plaintext_size );
    EVP_EncryptFinal_ex( ctx, ciphertext + ciphertext_size, &length );
    ciphertext_size += length;
    /* Get tag */
    EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag );

    EVP_CIPHER_CTX_reset( ctx );

    return ciphertext_size;
}

static uint32_t aead_encrypt2( const uint8_t* plaintext, uint32_t plaintext_size
        ,const uint8_t* plaintext_tail, uint32_t tail_size
        ,const uint8_t* aad, uint32_t aad_size
        ,const uint8_t* key, const uint8_t* iv
        ,uint8_t* ciphertext, uint8_t* tag, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx )
{
    /* Set cipher type and mode */
    EVP_EncryptInit_ex( ctx, cipher, nullptr, key, iv );
    /* Zero or more calls to specify any AAD */
    int length = 0;
    EVP_EncryptUpdate( ctx, nullptr, &length, aad, aad_size );
    /* Encrypt plaintext */
    int ciphertext_size = 0;
    EVP_EncryptUpdate( ctx, ciphertext, &ciphertext_size, plaintext, plaintext_size );
    EVP_EncryptUpdate( ctx, ciphertext+ciphertext_size, &length, plaintext_tail, tail_size );
    ciphertext_size += length;
    EVP_EncryptFinal_ex( ctx, ciphertext + ciphertext_size, &length );
    ciphertext_size += length;
    /* Get tag */
    EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag );

    EVP_CIPHER_CTX_reset( ctx );

    return ciphertext_size;
}

static uint32_t aead_decrypt( const uint8_t* ciphertext, uint32_t ciphertext_size
        ,const uint8_t* aad, uint32_t aad_size, const uint8_t* tag
        ,const uint8_t* key, const uint8_t* iv
        ,uint8_t* plaintext, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx )
{
    /* Initialise the decryption operation. */
    EVP_DecryptInit_ex( ctx, cipher, nullptr, key, iv );
    // AAD data. This can be called zero or more times as
    int len;
    EVP_DecryptUpdate( ctx, nullptr, &len, aad, aad_size );
    // ciphertext
    EVP_DecryptUpdate( ctx, plaintext, &len, ciphertext, ciphertext_size );
    int plaintext_size = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag );
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    int ret = EVP_DecryptFinal_ex( ctx, plaintext + len, &len );
    plaintext_size += len;

    EVP_CIPHER_CTX_reset( ctx );

    if( ret > 0 )
        return static_cast<uint32_t>( plaintext_size );
    else
        return 0;
}

static void fill_nonce(
        uint8_t* nonce, const uint8_t* static_iv, uint64_t& counter, uint32_t iv_size ) noexcept
{
    std::copy_n( static_iv, EVP_MAX_IV_LENGTH, nonce );
    uint64_t sequence_in_net_order = htobe64(counter);
    ++counter;
    uint32_t xor_offset = iv_size - sizeof(sequence_in_net_order);
    auto* uint64_iv = reinterpret_cast<uint64_t*>( nonce + xor_offset );
    *uint64_iv ^= sequence_in_net_order;
}

TlsCipherSuite::TlsCipherSuite() noexcept
        :m_ctx{ EVP_CIPHER_CTX_new() }
{}

TlsCipherSuite::~TlsCipherSuite() noexcept
{
    if( m_ctx != nullptr )
        EVP_CIPHER_CTX_free( m_ctx );
}

void TlsCipherSuite::copy_instance_data( TlsCipherSuite& other )
{
    m_ctx    = other.m_ctx;
    m_cipher = other.m_cipher;
    std::copy_n( other.m_sender_key  , sizeof(m_sender_key)  , m_sender_key );
    std::copy_n( other.m_sender_iv   , sizeof(m_sender_iv   ), m_sender_iv   );
    std::copy_n( other.m_receiver_key, sizeof(m_receiver_key), m_receiver_key);
    std::copy_n( other.m_receiver_iv , sizeof(m_receiver_iv ), m_receiver_iv );
    m_sender_counter   = other.m_sender_counter;
    m_receiver_counter = other.m_receiver_counter;
    m_digest      = other.m_digest;
    m_key_size    = other.m_key_size;
    m_digest_size = other.m_digest_size;
}
TlsCipherSuite::TlsCipherSuite( TlsCipherSuite&& other ) noexcept
{
    copy_instance_data( other );
    other.m_ctx = nullptr;
}
TlsCipherSuite& TlsCipherSuite::operator=( TlsCipherSuite&& other ) noexcept
{
    if( &other == this )
        return *this;

    copy_instance_data( other );
    other.m_ctx = nullptr;

    return *this;
}

bool TlsCipherSuite::is_supported_cipher_suite( record::CipherSuite cipher_suite )
{
    switch( cipher_suite.num() )
    {
        case record::TLS_AES_128_GCM_SHA256.num():
        case record::TLS_AES_256_GCM_SHA384.num():
        case record::TLS_CHACHA20_POLY1305_SHA256.num():
            return true;
        default:
            return false;
    }
}

void TlsCipherSuite::set_cipher_suite( record::CipherSuite cipher_suite )
{
    switch( cipher_suite.num() )
    {
        case record::TLS_AES_128_GCM_SHA256.num():
            m_cipher = EVP_aes_128_gcm();
            m_digest = EVP_sha256();
            m_key_size = 16;
            m_digest_size = SHA256_DIGEST_LENGTH;
            break;
        case record::TLS_AES_256_GCM_SHA384.num():
            m_cipher = EVP_aes_256_gcm();
            m_digest = EVP_sha384();
            m_key_size = 32;
            m_digest_size = SHA384_DIGEST_LENGTH;
            break;
        case record::TLS_CHACHA20_POLY1305_SHA256.num():
            m_cipher = EVP_chacha20_poly1305();
            m_digest = EVP_sha256();
            m_key_size = 32;
            m_digest_size = SHA256_DIGEST_LENGTH;
            break;
        default:
            char buff[4];
            std::to_chars(buff, buff+sizeof(buff),cipher_suite.num(),16);
            throw std::out_of_range("TlsCipherSuite not defined for "
                                    +std::string(buff, sizeof(buff)) );
    }
}

uint32_t TlsCipherSuite::encrypt(
        const uint8_t* plaintext, uint32_t plaintext_size, const uint8_t* aad, uint32_t aad_size,
        uint8_t* ciphertext, uint8_t* tag ) noexcept
{
    uint8_t nonce[EVP_MAX_IV_LENGTH];
    fill_nonce( nonce, m_sender_iv, m_sender_counter, iv_size() );

    return aead_encrypt( plaintext, plaintext_size, aad, aad_size, m_sender_key, nonce
                         ,ciphertext, tag, m_cipher, m_ctx );
}

uint32_t TlsCipherSuite::encrypt2(
        const uint8_t* plaintext, uint32_t plaintext_size,
        const uint8_t* plaintext_tail, uint32_t tail_size,
        const uint8_t* aad, uint32_t aad_size, uint8_t* ciphertext, uint8_t* tag ) noexcept
{
    uint8_t nonce[EVP_MAX_IV_LENGTH];
    fill_nonce( nonce, m_sender_iv, m_sender_counter, iv_size() );

    return aead_encrypt2( plaintext, plaintext_size, plaintext_tail, tail_size
                          , aad, aad_size, m_sender_key, nonce
                          , ciphertext, tag, m_cipher, m_ctx );
}

uint32_t TlsCipherSuite::decrypt(
        const uint8_t* ciphertext, uint32_t ciphertext_size,
        const uint8_t* aad, uint32_t aad_size, const uint8_t* tag, uint8_t* plaintext ) noexcept
{
    uint8_t nonce[EVP_MAX_IV_LENGTH];
    fill_nonce( nonce, m_receiver_iv, m_receiver_counter, iv_size() );

    return aead_decrypt( ciphertext, ciphertext_size, aad, aad_size, tag, m_receiver_key, nonce
                         , plaintext, m_cipher, m_ctx );
}

}
