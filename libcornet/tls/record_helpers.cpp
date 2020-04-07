/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tls/record_helpers.hpp>

#include <endian.h>
#include <algorithm>
#include <string>

#include <libcornet/tls/types.hpp>
#include <libcornet/tls/record_layer.hpp>
#include <libcornet/crypto.hpp>
#include <libcornet/tls/crypto/tls_handshake.hpp>
namespace crypto = pioneer19::cornet::crypto;

namespace pioneer19::cornet::tls13
{

// legacy session without backward compatibility is zero size array
template< bool just_size >
uint32_t legacy_session_id( uint8_t* buffer )
{
    auto* legacy_session = reinterpret_cast<record::LegacySessionId*>(buffer);
    uint32_t record_size = sizeof( record::LegacySessionId );

    if constexpr( !just_size )
        legacy_session->size = 0;

    return record_size;
}

struct RecordVector8
{
    uint8_t size;

    void finalize( uint8_t content_size ) { size = content_size; }
};

// legacy compression methods MUST contain exactly one byte, set to zero
template< bool just_size >
uint32_t legacy_compression_methods( uint8_t* buffer )
{
    auto* legacy_compression_methods = reinterpret_cast<RecordVector8*>(buffer);
    uint32_t record_size = sizeof( RecordVector8 );

    if constexpr( !just_size )
    {
        auto* compression_method_ptr = buffer + record_size;
        *compression_method_ptr = 0;
    }
    uint32_t data_size = 1;
    record_size += data_size;

    if constexpr( !just_size )
        legacy_compression_methods->finalize( data_size );

    return record_size;
}

struct RecordVector16
{
    uint16_t m_size;

    void finalize( uint16_t content_size ) { m_size = htobe16(content_size); }
};

template<bool just_size>
uint32_t cipher_suites( uint8_t* buffer )
{
    // CipherSuite cipher_suites<2..2^16-2>;
    auto* cipher_suites_list = reinterpret_cast<RecordVector16*>(buffer);
    uint32_t record_size = sizeof( RecordVector16 );

    if constexpr( !just_size )
    {
        auto* cipher_suite = reinterpret_cast<record::CipherSuite*>( buffer + record_size );
        cipher_suite[0] = record::TLS_CHACHA20_POLY1305_SHA256;
        cipher_suite[1] = record::TLS_AES_128_GCM_SHA256;
        cipher_suite[2] = record::TLS_AES_256_GCM_SHA384;
    }
    uint32_t data_size = 3*sizeof(record::CipherSuite);
    record_size += data_size;

    if constexpr( !just_size )
        cipher_suites_list->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t host_name( const std::string& hostname, uint8_t* buffer )
{
    auto* host_name = reinterpret_cast<record::HostName*>( buffer );
    uint32_t record_size = sizeof( record::HostName );

    uint32_t data_size = hostname.size();
    if constexpr( !just_size )
        std::copy_n( hostname.data(), data_size, buffer + record_size );
    record_size += data_size;

    if constexpr( !just_size )
        host_name->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t server_name( const std::string& hostname, uint8_t* buffer )
{
    auto* server_name = reinterpret_cast<record::ServerName*>( buffer );
    uint32_t record_size = sizeof( record::ServerName );

    if constexpr( !just_size )
        record_size = server_name->init();

    uint32_t data_size = host_name<just_size>( hostname, buffer + record_size );
    record_size += data_size;

    return record_size;
}

template< bool just_size >
static uint32_t server_name_list( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    auto* server_name_list = reinterpret_cast<record::ServerNameList*>( buffer );
    uint32_t record_size = sizeof( record::ServerNameList );

    uint32_t data_size = server_name<just_size>( *record_cryptor.connect_sni, buffer + record_size );
    record_size += data_size;

    if constexpr( !just_size )
        server_name_list->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t named_group_list( uint8_t* buffer )
{
    auto* named_group_list = reinterpret_cast<record::NamedGroupList*>( buffer );
    uint32_t record_size = sizeof( record::NamedGroupList );

    if constexpr( !just_size )
    {
        auto* named_group = reinterpret_cast<record::NamedGroup*>( buffer + record_size );
        named_group[0] = hton_named_group(record::NamedGroup::X25519);
        named_group[1] = hton_named_group(record::NamedGroup::SECP256R1);
        named_group[2] = hton_named_group(record::NamedGroup::X448);
        named_group[3] = hton_named_group(record::NamedGroup::SECP384R1);
        named_group[4] = hton_named_group(record::NamedGroup::SECP521R1);
    }
    uint32_t data_size = 5 * sizeof( record::NamedGroup );
    record_size += data_size;

    if constexpr( !just_size )
        named_group_list->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t protocol_name( const std::string& name, uint8_t* buffer )
{
    auto* protocol_name = reinterpret_cast<record::ProtocolName*>( buffer );
    uint32_t record_size = sizeof( record::ProtocolName );

    uint32_t data_size = name.size();
    if constexpr( !just_size )
        std::copy_n( name.data(), data_size, buffer + record_size );
    record_size += data_size;

    if constexpr( !just_size )
        protocol_name->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t protocol_name_list( uint8_t* buffer )
{
    auto* protocol_name_list = reinterpret_cast<record::ProtocolNameList*>( buffer );
    uint32_t record_size = sizeof( record::ProtocolNameList );

    // "h2"
    // "http/1.1"
    static const std::string http1_1 = "http/1.1";
    uint32_t data_size = protocol_name<just_size>( http1_1, buffer + record_size );
    record_size += data_size;

    if constexpr( !just_size )
        protocol_name_list->finalize( data_size );

    return record_size;
}

template< bool just_size >
uint32_t supported_versions_extension_data( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{   /*
     * struct {
     *     select (Handshake.msg_type) {
     *         case client_hello:
     *              ProtocolVersion versions<2..254>;
     *         case server_hello: // and HelloRetryRequest
     *              ProtocolVersion selected_version;
     *     };
     * } SupportedVersions;
     */
    switch( record_cryptor.m_hello_type )
    {
        case crypto::TlsHandshake::HelloType::ClientHello:
        {
            auto* supported_versions = reinterpret_cast<record::SupportedVersions*>( buffer );
            uint32_t record_size = sizeof( record::SupportedVersions );

            if constexpr( !just_size )
            {
                auto* protocol_versions = reinterpret_cast<record::ProtocolVersion*>( buffer + record_size );
                protocol_versions[0] = record::PROTOCOL_VERSION_TLS13;
            }
            uint32_t data_size = 1 * sizeof( record::ProtocolVersion );
            record_size += data_size;

            if constexpr( !just_size )
                supported_versions->finalize( data_size );

            return record_size;
        }
        case crypto::TlsHandshake::HelloType::ServerHello:
        case crypto::TlsHandshake::HelloType::HelloRetry:
        {
            if constexpr( !just_size )
            {
                auto* protocol_versions = reinterpret_cast<record::ProtocolVersion*>( buffer );
                *protocol_versions = record::PROTOCOL_VERSION_TLS13;
            }
            return sizeof(record::ProtocolVersion);
        }
        default:
            throw std::runtime_error( "supported_versions_extension_data() got unknown hello type "
                                      +std::to_string(static_cast<uint8_t>(record_cryptor.m_hello_type)) );
    }
}

template< bool just_size >
uint32_t psk_key_exchange_modes_extension_data( uint8_t* buffer )
{
    auto* psk_kex_modes = reinterpret_cast<record::PskKeyExchangeModes*>( buffer );
    uint32_t record_size = sizeof( record::PskKeyExchangeModes );

    if constexpr( !just_size )
    {
        auto* psk_ke_mode = reinterpret_cast<record::PskKeyExchangeMode*>( buffer + record_size );
        psk_ke_mode[0] = record::PskKeyExchangeMode::PSK_DHE_KE;
    }
    uint32_t data_size = 1*sizeof( record::PskKeyExchangeMode );
    record_size += data_size;

    if constexpr( !just_size )
        psk_kex_modes->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t signature_scheme_list( uint8_t* buffer )
{
    auto* signature_scheme_list = reinterpret_cast<record::SignatureSchemeList*>( buffer );
    uint32_t record_size = sizeof( record::SignatureSchemeList );

    if constexpr( !just_size )
    {
        auto* signature_scheme = reinterpret_cast<record::SignatureScheme*>( buffer + record_size );
        /* ECDSA algorithms */
        signature_scheme[0] = record::SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256;
        signature_scheme[1] = record::SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384;
        signature_scheme[2] = record::SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512;
        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        signature_scheme[3] = record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256;
        signature_scheme[4] = record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384;
        signature_scheme[5] = record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512;
        /* EdDSA algoriths */
        signature_scheme[6] = record::SIGNATURE_SCHEME_ED25519;
        signature_scheme[7] = record::SIGNATURE_SCHEME_ED448;
        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        signature_scheme[8]  = record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256;
        signature_scheme[9]  = record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384;
        signature_scheme[10] = record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512;
    }
    uint32_t data_size = 11* sizeof(record::SignatureScheme);
    record_size += data_size;

    if constexpr( !just_size )
        signature_scheme_list->finalize( data_size );

    return record_size;
}

template< bool just_size >
uint32_t key_share_entry( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    auto* entry = reinterpret_cast<record::KeyShareEntry*>( buffer );
    uint32_t record_size = sizeof( record::KeyShareEntry );

    if constexpr( !just_size )
        entry->init( record_cryptor.dhe_group().named_group() );

    size_t data_size = 0;
    if constexpr( just_size )
        data_size = record_cryptor.dhe_group().public_key_size();
    else // !just_size
        data_size = record_cryptor.dhe_group().copy_public_key( buffer+record_size );

    record_size += data_size;

    if constexpr( !just_size )
        entry->finalize( data_size );

    return record_size;
}

template< bool just_size >
static uint32_t key_share_entries( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    // Here can be many entries for different private keys
    uint32_t data_size = key_share_entry<just_size>( record_cryptor, buffer );
    return data_size;
}

template< bool just_size >
static uint32_t key_share_client_hello( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{   /*
     * struct {
     *     KeyShareEntry client_shares<0..2^16-1>;
     * } KeyShareClientHello;
     */
    auto* extension_data = reinterpret_cast<record::KeyShareClientHello*>( buffer );
    uint32_t record_size = sizeof( record::KeyShareClientHello );

    uint32_t data_size = key_share_entries<just_size>( record_cryptor, buffer + record_size );
    record_size += data_size;

    if constexpr( !just_size )
        extension_data->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t key_share_extension_data( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    switch( record_cryptor.m_hello_type )
    {
        case crypto::TlsHandshake::HelloType::ClientHello:
            return key_share_client_hello<just_size>( record_cryptor, buffer );
        case crypto::TlsHandshake::HelloType::ServerHello:
            return key_share_entry<just_size>( record_cryptor, buffer );
        default:
            throw std::runtime_error( "key_share_extension_data() unknown hello type "
                                      +std::to_string(static_cast<uint8_t>(record_cryptor.m_hello_type)) );
    }
}

template< bool just_size >
uint32_t extension_helper( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer, record::ExtensionType extension_type )
{
    auto* extension = reinterpret_cast<record::Extension*>( buffer );
    uint32_t record_size = sizeof( record::Extension );

    if constexpr( !just_size )
        record_size = extension->init( extension_type );
    uint16_t data_size = 0;
    switch( extension_type )
    {
        case record::ExtensionType::SERVER_NAME:
            data_size = server_name_list<just_size>(
                    record_cryptor, buffer + record_size );
            break;
        case record::ExtensionType::MAX_FRAGMENT_LENGTH:
        case record::ExtensionType::STATUS_REQUEST:
            break;
        case record::ExtensionType::SUPPORTED_GROUPS:
            data_size = named_group_list<just_size>( buffer + record_size );
            break;
        case record::ExtensionType::SIGNATURE_ALGORITHMS:
            data_size = signature_scheme_list<just_size>( buffer + record_size );
            break;
        case record::ExtensionType::USE_SRTP:
        case record::ExtensionType::HEARTBEAT:
            break;
        case record::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            data_size = protocol_name_list<just_size>( buffer + record_size );
            break;
        case record::ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP:
        case record::ExtensionType::CLIENT_CERTIFICATE_TYPE:
        case record::ExtensionType::SERVER_CERTIFICATE_TYPE:
        case record::ExtensionType::PADDING:
        case record::ExtensionType::PRE_SHARED_KEY:
        case record::ExtensionType::EARLY_DATA:
            break;
        case record::ExtensionType::SUPPORTED_VERSIONS:
            data_size = supported_versions_extension_data<just_size>(
                    record_cryptor, buffer + record_size );
            break;
        case record::ExtensionType::COOKIE:
            break;
        case record::ExtensionType::PSK_KEY_EXCHANGE_MODES:
            data_size = psk_key_exchange_modes_extension_data<just_size>( buffer + record_size );
            break;
        case record::ExtensionType::CERTIFICATE_AUTHORITIES:
        case record::ExtensionType::OID_FILTERS:
        case record::ExtensionType::POST_HANDSHAKE_AUTH:
        case record::ExtensionType::SIGNATURE_ALGORITHMS_CERT:
            break;
        case record::ExtensionType::KEY_SHARE:
            data_size = key_share_extension_data<just_size>( record_cryptor, buffer + record_size );
            break;
        default:
            throw std::runtime_error("extension_helper not implemented for extension "
                               + std::to_string( static_cast<uint16_t>(extension_type) ) );
    }
    if constexpr( !just_size )
        extension->finalize( data_size );

    record_size += data_size;
    return record_size;
}

template< bool just_size >
uint32_t extension_server_name( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    return extension_helper<just_size>( record_cryptor
            , buffer, record::ExtensionType::SERVER_NAME );
}

template< bool just_size >
uint32_t extension_supported_groups( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    return extension_helper<just_size>( record_cryptor
                                        , buffer, record::ExtensionType::SUPPORTED_GROUPS );
}

static uint32_t create_alpn_extension( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    return extension_helper<false>(record_cryptor
            , buffer,record::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION );
}

template< bool just_size >
uint32_t extension_signature_algorithms( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    return extension_helper<just_size>( record_cryptor
            , buffer, record::ExtensionType::SIGNATURE_ALGORITHMS );
}

template< bool just_size >
uint32_t extension_supported_versions_list( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return extension_helper<just_size>(record_cryptor
                                       , buffer, record::ExtensionType::SUPPORTED_VERSIONS );
}

template< bool just_size >
uint32_t extension_psk_kex_modes( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    return extension_helper<just_size>( record_cryptor
            , buffer, record::ExtensionType::PSK_KEY_EXCHANGE_MODES );
}

template< bool just_size>
uint32_t extension_key_share( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    return extension_helper<just_size>( record_cryptor
            , buffer, record::ExtensionType::KEY_SHARE );
}

template< bool just_size >
uint32_t client_hello_extensions( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    auto* extension_list = reinterpret_cast<RecordVector16*>(buffer);
    uint32_t record_size = sizeof( RecordVector16 );

    uint32_t data_size = 0;
    data_size += extension_server_name<just_size>( record_cryptor
            , buffer + record_size + data_size );
    data_size += extension_supported_groups<just_size>( record_cryptor
            , buffer + record_size + data_size );
    //offset += create_alpn_extension( record_layer, buffer+record_size + data_size );
    data_size += extension_signature_algorithms<just_size>( record_cryptor
            , buffer+record_size + data_size);
    data_size += extension_supported_versions_list<just_size>( record_cryptor
            , buffer+record_size+data_size);
    data_size += extension_psk_kex_modes<just_size>( record_cryptor
            , buffer + record_size + data_size );
    data_size += extension_key_share<just_size>(record_cryptor
            , buffer + record_size + data_size );

    record_size += data_size;

    if constexpr( !just_size )
        extension_list->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t client_hello_message( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    auto* client_hello = reinterpret_cast<record::ClientHello*>(buffer);
    uint32_t record_size = sizeof( record::ClientHello );

    if constexpr( !just_size )
    {
        client_hello->init();
        ::crypto::random_bytes( client_hello->random.data(), client_hello->random.size() );
    }

    uint32_t data_size = 0;
    data_size += legacy_session_id<just_size>( buffer + record_size + data_size );
    data_size += cipher_suites<just_size>( buffer + record_size + data_size );
    data_size += legacy_compression_methods<just_size>( buffer + record_size + data_size );
    data_size += client_hello_extensions<just_size>( record_cryptor
            , buffer + record_size + data_size );

    record_size += data_size;

    return record_size;
}

template< bool just_size >
uint32_t server_hello_extensions( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    auto* extension_list = reinterpret_cast<RecordVector16*>(buffer);
    uint32_t record_size = sizeof( RecordVector16 );

    uint32_t data_size = 0;
    data_size += extension_supported_versions_list<just_size>( record_cryptor
                                                              , buffer+record_size+data_size);
    data_size += extension_key_share<just_size>( record_cryptor
                                                 , buffer + record_size + data_size );
    record_size += data_size;

    if constexpr( !just_size )
        extension_list->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t server_hello_message( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{   /* struct {
     *     ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
     *     Random random;
     *     opaque legacy_session_id_echo<0..32>;
     *     CipherSuite cipher_suite;
     *     uint8 legacy_compression_method = 0;
     *     Extension extensions<6..2^16-1>;
     * } ServerHello;
     */
    auto* server_hello = reinterpret_cast<record::ServerHello*>(buffer);
    uint32_t record_size = sizeof( record::ServerHello );

    if constexpr( !just_size )
    {
        server_hello->init();
        ::crypto::random_bytes( server_hello->random.data(), server_hello->random.size() );
        std::copy_n( record_cryptor.legacy_session
                     ,sizeof(record::LegacySessionId) +
                      reinterpret_cast<record::LegacySessionId*>(record_cryptor.legacy_session)->size
                     ,buffer + record_size );
    }

    uint32_t data_size = 0;
    data_size += sizeof(record::LegacySessionId) +
            reinterpret_cast<record::LegacySessionId*>(record_cryptor.legacy_session)->size;
    if constexpr( !just_size )
    {
        auto* cipher_suite = reinterpret_cast<record::CipherSuite*>(buffer + record_size + data_size);
        *cipher_suite = record_cryptor.cipher_suite();
    }
    data_size += sizeof(record::CipherSuite);
    if constexpr( !just_size )
    {
        auto* legacy_compression_method = reinterpret_cast<uint8_t*>(buffer + record_size + data_size);
        *legacy_compression_method = 0;
    }
    data_size += sizeof(uint8_t);
    data_size += server_hello_extensions<just_size>( record_cryptor, buffer + record_size + data_size );
    record_size += data_size;

    return record_size;
}

template< bool just_size >
uint32_t finished_message( crypto::TlsHandshake& tls_handshake
        , uint8_t* buffer, bool from_server )
{
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    uint32_t data_size = 0;
    if constexpr( !just_size )
        data_size = tls_handshake.handshake_finished_create_verify_data( buffer, from_server );
    else
        data_size = tls_handshake.m_record_cryptor.digest_size();

    return data_size;
}

template< bool just_size >
uint32_t empty_record_vector16( uint8_t* buffer )
{   /* struct {
     *     Extension extensions<0..2^16-1>;
     * } EncryptedExtensions;
     */
    auto* extension_list = reinterpret_cast<RecordVector16*>(buffer);
    uint32_t record_size = sizeof( RecordVector16 );

    uint32_t data_size = 0;

    if constexpr( !just_size )
        extension_list->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t empty_record_vector8( uint8_t* buffer )
{
    auto* record_vector8 = reinterpret_cast<RecordVector8*>(buffer);
    uint32_t record_size = sizeof( RecordVector8 );

    uint32_t data_size = 0;

    if constexpr( !just_size )
        record_vector8->finalize( data_size );

    return record_size;
}

using RecordVector24 = record::NetUint24;

template< bool just_size >
uint32_t cert_data( uint8_t* der_cert, uint32_t cert_size, uint8_t* buffer )
{   // opaque cert_data<1..2^24-1>; DER-encoded X.509 certificate
    auto* der_certificate = reinterpret_cast<RecordVector24*>(buffer);
    uint32_t record_size = sizeof( RecordVector24 );

    uint32_t data_size = 0;
    if constexpr( !just_size )
        std::copy_n( der_cert, cert_size, buffer + record_size + data_size );

    data_size   += cert_size;
    record_size += data_size;

    if constexpr( !just_size )
        der_certificate->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t certificate_entry( uint8_t* der_cert, uint32_t cert_size, uint8_t* buffer )
{   /*
     * enum {
     *     X509(0),
     *     RawPublicKey(2),
     *     (255)
     * } CertificateType;
     * struct {
     *     select (certificate_type) {
     *         case RawPublicKey:
     *             // From RFC 7250 ASN.1_subjectPublicKeyInfo
     *             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
     *         case X509:
     *             opaque cert_data<1..2^24-1>;
     *     };
     *     Extension extensions<0..2^16-1>;
     * } CertificateEntry;
     */
    // opaque cert_data<1..2^24-1>;
    // Extension extensions<0..2^16-1>;
    uint32_t record_size = 0;

    uint32_t data_size = 0;
    data_size += cert_data<just_size>( der_cert, cert_size, buffer+record_size+data_size );
    data_size += empty_record_vector16<just_size>( buffer + record_size + data_size );
    record_size += data_size;

    return record_size;
}
template< bool just_size >
uint32_t certificate_chain( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    // FIXME: currently only single certificate in chain supported
    auto record_size = certificate_entry<just_size>( record_cryptor.domain_keys->der_cert_chain
                                         ,record_cryptor.domain_keys->der_chain_size, buffer );
    return record_size;
}
template< bool just_size >
uint32_t certificate_list( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{   /*
     * enum {
     *     X509(0),
     *     RawPublicKey(2),
     *     (255)
     * } CertificateType;
     * struct {
     *     select (certificate_type) {
     *         case RawPublicKey:
     *             // From RFC 7250 ASN.1_subjectPublicKeyInfo
     *             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
     *         case X509:
     *             opaque cert_data<1..2^24-1>;
     *     };
     *     Extension extensions<0..2^16-1>;
     * } CertificateEntry;
     * struct {
     *     opaque certificate_request_context<0..2^8-1>;
     *     CertificateEntry certificate_list<0..2^24-1>;
     * } Certificate;
     */
    // CertificateEntry certificate_list<0..2^24-1>;
    auto* certificate_list = reinterpret_cast<RecordVector24*>(buffer);
    uint32_t record_size = sizeof( RecordVector24 );

    uint32_t data_size = 0;
    data_size += certificate_entry<just_size>(
            record_cryptor.domain_keys->der_domain_cert
            , record_cryptor.domain_keys->der_cert_size, buffer + record_size + data_size );
    data_size += certificate_chain<just_size>( record_cryptor, buffer + record_size + data_size );
    record_size += data_size;

    if constexpr( !just_size )
        certificate_list->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t certificate_message( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{   /*
     * enum {
     *     X509(0),
     *     RawPublicKey(2),
     *     (255)
     * } CertificateType;
     * struct {
     *     select (certificate_type) {
     *         case RawPublicKey:
     *             // From RFC 7250 ASN.1_subjectPublicKeyInfo
     *             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
     *         case X509:
     *             opaque cert_data<1..2^24-1>;
     *     };
     *     Extension extensions<0..2^16-1>;
     * } CertificateEntry;
     * struct {
     *     opaque certificate_request_context<0..2^8-1>;
     *     CertificateEntry certificate_list<0..2^24-1>;
     * } Certificate;
     */
    uint32_t record_size = 0;

    uint32_t data_size = 0;
    // empty certificate_request_context
    data_size += empty_record_vector8<just_size>( buffer+record_size+data_size );
    data_size += certificate_list<just_size>( record_cryptor, buffer + record_size + data_size );
    record_size += data_size;

    return record_size;
}
template< bool just_size >
uint32_t certificate_verify_signature( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{   // opaque signature<0..2^16-1>;
    auto* signature = reinterpret_cast<RecordVector16*>(buffer);
    uint32_t record_size = sizeof( RecordVector16 );

    uint32_t data_size = 0;
    if constexpr( !just_size )
    {
        data_size = record_cryptor.handshake_certificate_verify_create_signature(
                buffer + record_size + data_size, 1024 );
    } else
        assert( !just_size ); // FIXME: not implemented
    record_size += data_size;

    if constexpr( !just_size )
        signature->finalize( data_size );

    return record_size;
}
template< bool just_size >
uint32_t certificate_verify_message( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{   /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    auto* certificate_verify = reinterpret_cast<record::CertificateVerify*>(buffer);
    uint32_t record_size = sizeof( record::CertificateVerify );

    if constexpr( !just_size )
        certificate_verify->algorithm = record_cryptor.cert_signature_scheme;

    uint32_t data_size = 0;
    data_size += certificate_verify_signature<just_size>(
            record_cryptor, buffer + record_size + data_size );
    record_size += data_size;

    return record_size;
}

template< bool just_size >
uint32_t handshake_message( crypto::TlsHandshake& tls_handshake
        ,record::HandshakeType handshake_type, uint8_t* buffer, bool from_server = true )
{
    auto* handshake_message = reinterpret_cast<record::Handshake*>(buffer);
    uint32_t record_size = sizeof( record::Handshake );

    if constexpr( !just_size )
        handshake_message->init( handshake_type );

    uint32_t data_size = 0;
    switch( handshake_type )
    {
        case record::HandshakeType::CLIENT_HELLO:
            data_size = client_hello_message<just_size>( tls_handshake, buffer + record_size );
            break;
        case record::HandshakeType::SERVER_HELLO:
            data_size = server_hello_message<just_size>( tls_handshake, buffer + record_size );
            break;
        case record::HandshakeType::NEW_SESSION_TICKET:
        case record::HandshakeType::END_OF_EARLY_DATA:
            break;
        case record::HandshakeType::ENCRYPTED_EXTENSIONS:
            data_size = empty_record_vector16<just_size>( buffer + record_size );
            break;
        case record::HandshakeType::CERTIFICATE:
            data_size = certificate_message<just_size>( tls_handshake, buffer + record_size );
            break;
        case record::HandshakeType::CERTIFICATE_REQUEST:
            break;
        case record::HandshakeType::CERTIFICATE_VERIFY:
            data_size = certificate_verify_message<just_size>( tls_handshake, buffer + record_size );
            break;
        case record::HandshakeType::FINISHED:
            data_size = finished_message<just_size>( tls_handshake, buffer + record_size, from_server );
            break;
        case record::HandshakeType::KEY_UPDATE:
        case record::HandshakeType::MESSAGE_HASH:
            break;
    }
    record_size += data_size;

    if constexpr( !just_size )
        handshake_message->finalize( data_size );

    return record_size;
}

template< bool just_size >
uint32_t client_hello_record( crypto::TlsHandshake& record_cryptor
        , uint8_t* buffer )
{
    auto* plaintext_record = reinterpret_cast<record::TlsPlaintext*>( buffer );
    uint32_t record_size = sizeof( record::TlsPlaintext );

    if constexpr( !just_size )
        plaintext_record->init( record::ContentType::HANDSHAKE, record::PROTOCOL_VERSION_TLS10 );

    uint32_t data_size = handshake_message<just_size>( record_cryptor,
            record::HandshakeType::CLIENT_HELLO, buffer + record_size );
    record_size += data_size;

    if constexpr( !just_size )
        plaintext_record->finalize( data_size );

    return record_size;
}
uint32_t RecordHelpers::client_hello_record_buffer_size( crypto::TlsHandshake& record_cryptor )
{
    return client_hello_record<true>( record_cryptor, nullptr );
}

uint32_t RecordHelpers::create_client_hello_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return client_hello_record<false>( record_cryptor, buffer );
}
template< bool just_size >
uint32_t handshake_record( record::HandshakeType handshake_type
        , crypto::TlsHandshake& record_cryptor, uint8_t* buffer, bool from_server = true )
{
    auto* plaintext_record = reinterpret_cast<record::TlsPlaintext*>( buffer );
    uint32_t record_size = sizeof( record::TlsPlaintext );

    if constexpr( !just_size )
        plaintext_record->init( record::ContentType::HANDSHAKE );

    uint32_t data_size = handshake_message<just_size>( record_cryptor,
            handshake_type, buffer + record_size, from_server );
    record_size += data_size;

    if constexpr( !just_size )
        plaintext_record->finalize( data_size );

    return record_size;
}
uint32_t RecordHelpers::create_client_finished_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return handshake_record<false>( record::HandshakeType::FINISHED, record_cryptor, buffer
                                    , false );
}
uint32_t RecordHelpers::client_finished_record_buffer_size( crypto::TlsHandshake& record_cryptor )
{
    return handshake_record<true>( record::HandshakeType::FINISHED, record_cryptor, nullptr
                                    , false );
}
uint32_t RecordHelpers::server_hello_record_buffer_size(
        crypto::TlsHandshake& record_cryptor )
{
    return handshake_record<true>( record::HandshakeType::SERVER_HELLO
                                    , record_cryptor, nullptr, true );
}

uint32_t RecordHelpers::create_server_hello_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return handshake_record<false>( record::HandshakeType::SERVER_HELLO
                                    , record_cryptor, buffer, true );
}
uint32_t RecordHelpers::create_encrypted_extensions_record(
        crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return handshake_record<false>( record::HandshakeType::ENCRYPTED_EXTENSIONS
                                    , record_cryptor, buffer, true );
}
uint32_t RecordHelpers::create_certificate_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return handshake_record<false>( record::HandshakeType::CERTIFICATE
                                    , record_cryptor, buffer, true );
}
uint32_t RecordHelpers::create_certificate_verify_record(
        crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return handshake_record<false>( record::HandshakeType::CERTIFICATE_VERIFY
                                    , record_cryptor, buffer, true );
}
uint32_t RecordHelpers::create_server_finished_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer )
{
    return handshake_record<false>( record::HandshakeType::FINISHED, record_cryptor, buffer
                                    , true );
}

}
