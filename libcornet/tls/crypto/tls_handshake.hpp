/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <cstdint>
#include <utility>
#include <string>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <libcornet/tls/types.hpp>
#include <libcornet/tls/crypto/dhe_groups.hpp>
#include <libcornet/tls/crypto/record_ciphers.hpp>
#include <libcornet/tls/crypto/record_cryptor.hpp>
#include <libcornet/tls/key_store.hpp>

namespace pioneer19::cornet::tls13::crypto
{

class TlsHandshake
{
public:
    // common method
    ~TlsHandshake() noexcept;
    // client method
    TlsHandshake( RecordCryptor& record_cryptor, const std::string& sni, record::NamedGroup named_group );
    // server method
    TlsHandshake( RecordCryptor& record_cryptor, std::string& sni );

    // common methods
    void set_tls_cipher_suite( record::CipherSuite cipher_suite );
    void set_handshake_hello_key_share( record::NamedGroup named_group, const uint8_t* public_key,
                                        uint16_t key_size ) noexcept;
    void derive_client_server_traffic_secrets( bool from_server ) noexcept;
    // client methods
    // server methods

    DheGroup& dhe_group() noexcept { return m_named_group; }
    void set_named_group( record::NamedGroup named_group );

    [[nodiscard]]
    record::CipherSuite cipher_suite() const noexcept;

    void add_message( const uint8_t* data, size_t size );
    uint32_t current_transcript_hash( uint8_t* hash_out ) const noexcept;

    bool handshake_certificate_verify_do_verify_signature( record::SignatureScheme signature_scheme
            ,const uint8_t* signature, uint32_t signature_size, bool from_server=true );
    void handshake_set_certificate( X509* cert );
    uint32_t handshake_certificate_verify_create_signature( uint8_t* signature, uint32_t signature_size
            , bool from_server=true );

    uint32_t handshake_finished_create_verify_data( uint8_t* hmac_data, bool from_server = true );

    static const char* error_string();
    static const uint8_t* empty_early_secret( const EVP_MD* md ) noexcept;

    TlsHandshake()                                = delete;
    TlsHandshake( TlsHandshake&& )            = delete;
    TlsHandshake& operator=( TlsHandshake&& ) = delete;
    TlsHandshake( const TlsHandshake& )       = delete;
    TlsHandshake& operator=( const TlsHandshake& ) = delete;

    // common data
    union {
        const std::string* connect_sni;
        std::string*       accept_sni;
    };
    // opaque legacy_session_id<0..32>;
    uint8_t legacy_session[sizeof(record::LegacySessionId)+32]={0};
    // shared secret created using dhe after client/server hello key_share
    uint32_t dhe_shared_secret_size = 0;
    uint8_t  dhe_shared_secret[ std::max(EVP_MAX_KEY_LENGTH, OPENSSL_ECC_MAX_FIELD_BITS/8+1) ];
    enum class HelloType : uint8_t
    {
        ClientHello,
        ServerHello,
        HelloRetry,
    } m_hello_type = HelloType::ClientHello;
    // server data
    DomainKeys* domain_keys = nullptr;

    record::SignatureScheme cert_signature_scheme;

    RecordCryptor& m_record_cryptor;
private:
    friend class RecordCryptor;

    std::unique_ptr<uint8_t[]> m_data;
    uint8_t* m_handshake_secret = nullptr;
    uint8_t* m_client_handshake_traffic_secret = nullptr;
    uint8_t* m_server_handshake_traffic_secret = nullptr;
    X509*    m_certificate = nullptr;
    void init_handshake_stage_data();

    uint32_t handshake_certificate_verify_create_signed_data( uint8_t* signed_data, bool from_server );
    bool handshake_check_signed_data(
            const uint8_t* signature, uint32_t signature_size
            , const uint8_t* signed_data, uint32_t signed_data_size
            , int nid, const EVP_MD* md = nullptr );
    /**
     * sign data for certificate_verify handshake message and return signature size
     * @param signature
     * @param signature_size
     * @param data_to_sign
     * @param data_size
     * @param nid
     * @param md
     * @return
     */
    static uint32_t handshake_certificate_verify_sign_data( uint8_t* signature, uint32_t signature_size
            , const uint8_t* data_to_sign, uint32_t data_size
            , EVP_PKEY* pkey, int nid, const EVP_MD* md = nullptr );

    EVP_MD_CTX* m_messages_digest = nullptr;
    DheGroup    m_named_group;
    record::CipherSuite m_cipher_suite = record::TLS_PRIVATE_CIPHER_SUITE;
};

inline const char* TlsHandshake::error_string()
{
    return ERR_error_string( ERR_get_error(), nullptr );
}

inline void TlsHandshake::add_message( const uint8_t* data, size_t size )
{
    EVP_DigestUpdate( m_messages_digest, data, size );
}

inline void TlsHandshake::init_handshake_stage_data()
{
    auto hash_size = m_record_cryptor.digest_size();
    m_data.reset( new uint8_t[ 3 * hash_size ] );
    m_handshake_secret = m_data.get();
    m_client_handshake_traffic_secret = m_data.get() + hash_size ;
    m_server_handshake_traffic_secret = m_data.get() + 2*hash_size;
}

inline void TlsHandshake::set_named_group( record::NamedGroup named_group )
{
    m_named_group.set_dhe_group( named_group );
}

inline record::CipherSuite TlsHandshake::cipher_suite() const noexcept
{
    return m_cipher_suite;
}

}
