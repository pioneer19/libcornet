/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <endian.h>

#include <memory>
#include <string>
#include <libcornet/tls/types.hpp>
#include <libcornet/tls/parser_error.hpp>

namespace pioneer19::cornet::tls13::record
{

struct EmptyHook
{
    static void tls_plaintext( const TlsPlaintext* ) {}
    static void tls_handshake( const Handshake* ) {}
    static void client_hello_protocol_version( const ProtocolVersion* ) {}
    static void client_hello_random( const Random* ) {}
    static void client_hello_legacy_session_id( const LegacySessionId* ) {}
    static void client_hello_cipher_suites( const CipherSuite*, uint32_t ) {}
    static void client_hello_legacy_compression_methods( const uint8_t*, uint8_t ) {}
    static void server_hello_protocol_version( const ProtocolVersion* ) {}
    static void server_hello_random( const Random* ) {}
    static void server_hello_legacy_session_id( const LegacySessionId* ) {}
    static void server_hello_cipher_suites( const CipherSuite*, uint32_t ) {}
    static void server_hello_legacy_compression_methods( const uint8_t*, uint8_t ) {}
    static void extensions_list( uint16_t ) {}
    static void extension( ExtensionType, uint16_t ) {}
    static void extension_server_name( NameType, const uint8_t*, uint16_t ) {}
    static void extension_supported_version( ProtocolVersion ) {}
    static void named_group( NamedGroup ) {}
    static void signature_scheme( SignatureScheme ) {}
    static void psk_key_exchange_mode( PskKeyExchangeMode ) {}
    static void key_share_entry( NamedGroup, const uint8_t*, uint16_t ) {}
    static void certificate_request_context( const uint8_t*, uint32_t ) {}
    static void certificate_list( uint32_t ) {}
    static void cert_data(  CertificateType, const uint8_t*, uint32_t ) {}
    static void cert_verify_data( const SignatureScheme*, const uint8_t*, uint32_t ) {}
    static void finished_data( const uint8_t*, uint32_t ){}
    static void tls_alert( const Alert ){}
};

class Parser
{
public:
    Parser() = default;
    Parser( const Parser& )       = delete;
    Parser( Parser&& )            = delete;
    Parser& operator=( const Parser& ) = delete;
    Parser& operator=( Parser&& ) = delete;
    //~Parser() = default;

    template< typename Hook>
    std::pair<uint32_t,ParserError> parse_net_record( Hook* hook
            ,const char* char_buffer, uint32_t buffer_size );
    template< typename Hook>
    std::pair<uint32_t,ParserError> parse_net_record( Hook* hook
            , const uint8_t* buffer, uint32_t buffer_size );

    [[nodiscard]]
    const std::string& message_addon() const noexcept { return m_message_addon; }

private:
    template< typename Hook>
    ParserError parse_alert( Hook* hook
            ,const uint8_t* buffer, uint32_t buffer_size );
    template< typename Hook>
    ParserError parse_handshake( Hook* hook
            ,const uint8_t* buffer, uint32_t buffer_size );
    template< typename Hook >
    ParserError parse_client_hello_message( Hook* hook
            ,const uint8_t* buffer, uint32_t buffer_size );
    template< typename Hook >
    ParserError parse_server_hello_message( Hook* hook
            ,const uint8_t* buffer, uint32_t buffer_size );
    template<typename Hook>
    ParserError parse_encrypted_extensions( Hook* hook
            ,const uint8_t* buffer, uint16_t buffer_size
            ,HandshakeType handshake_type );
    template<typename Hook>
    ParserError parse_certificate( Hook* hook
            ,const uint8_t* buffer, uint16_t buffer_size );
    template<typename Hook>
    ParserError parse_certificate_verify( Hook* hook
            ,const uint8_t* buffer, uint16_t buffer_size );
    template<typename Hook>
    ParserError parse_finished( Hook* hook
            ,const uint8_t* buffer, uint16_t buffer_size );

    template<typename Hook>
    ParserError parse_certificate_entry( Hook* hook
            ,const uint8_t* buffer, uint16_t buffer_size, CertificateType cert_type = CertificateType::X509 );

    template< typename Hook >
    ParserError parse_extensions( Hook* hook
            ,const uint8_t* buffer, uint16_t buffer_size
            ,HandshakeType handshake_type );
    template< typename Hook >
    ParserError parse_extension_server_name( Hook* hook
            ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size );
    template< typename Hook >
    ParserError parse_extension_supported_versions( Hook* hook
            ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size
            ,HandshakeType handshake_type );
    template< typename Hook >
    ParserError parse_extension_key_share( Hook* hook
            ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size
            ,HandshakeType handshake_type );
    template< typename Hook >
    ParserError parse_extension_supported_groups( Hook* hook
            ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size );
    template< typename Hook >
    ParserError parse_extension_signature_algorithms( Hook* hook
            ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size );
    template< typename Hook >
    ParserError parse_extension_psk_key_exchange_modes( Hook* hook
            ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size );

    std::string m_message_addon;
};

ParserError print_net_record( const uint8_t* buffer, uint32_t size );

static inline bool parse_vec8( const uint8_t* buffer, uint32_t buffer_size
        ,const uint8_t*& data, uint8_t& data_size )
{
    if( sizeof(uint8_t) > buffer_size )
        return false;
    data_size = *buffer;
    if( ( sizeof(uint8_t) + data_size ) > buffer_size )
        return false;
    data = buffer + sizeof(uint8_t);

    return true;
}

static inline bool parse_vec16( const void* buffer, uint32_t buffer_size
        ,const uint8_t*& data, uint16_t& data_size, uint32_t prefix_size=0 )
{
    if( prefix_size+sizeof(uint16_t) > buffer_size )
        return false;
    data_size = be16toh(*reinterpret_cast<const uint16_t*>( (uint8_t*)buffer + prefix_size ) );
    if( ( prefix_size + sizeof(uint16_t) + data_size ) > buffer_size )
        return false;
    data = (uint8_t*)buffer + prefix_size + sizeof(uint16_t);

    return true;
}

static inline bool parse_vec24( const uint8_t* buffer, uint32_t buffer_size
        ,const uint8_t*& data, uint32_t& data_size, uint32_t prefix_size=0 )
{
    if( (prefix_size+sizeof(NetUint24)) > buffer_size )
        return false;
    data_size = reinterpret_cast<const NetUint24*>(buffer+prefix_size)->length();
    if( ( prefix_size + sizeof(NetUint24)+data_size ) > buffer_size )
        return false;
    data = buffer +prefix_size + sizeof(NetUint24);

    return true;
}

template< typename Hook >
std::pair<uint32_t,ParserError> Parser::parse_net_record( Hook* hook
        ,const char* char_buffer, uint32_t buffer_size )
{
    return parse_net_record<Hook>( hook, reinterpret_cast<const uint8_t*>(char_buffer), buffer_size );
}

template< typename Hook >
std::pair<uint32_t,ParserError> Parser::parse_net_record( Hook* hook
        ,const uint8_t* buffer, uint32_t buffer_size )
{
    const uint8_t* record_data;
    uint16_t record_data_size;
    if( !parse_vec16( buffer, buffer_size, record_data, record_data_size,
            sizeof(ContentType)+sizeof(ProtocolVersion) ) )
    {
        return {0,ParserError( ParserErrno::W_LOW_DATA_IN_NET_RECORD )};
    }

    auto tls_record = reinterpret_cast<const TlsPlaintext*>( buffer );
    hook->tls_plaintext( tls_record );

    switch( tls_record->type ) // ContentType in TlsPlaintext
    {
        case ContentType::INVALID:
        case ContentType::CHANGE_CIPHER_SPEC:
        case ContentType::ALERT:
        {
            auto err = parse_alert<Hook>( hook, record_data, record_data_size );
            if( err ) return { 0, err };
            break;
        }
            break;
        case ContentType::HANDSHAKE:
        {
            auto hs_err = parse_handshake<Hook>( hook, record_data, record_data_size );
            if( hs_err ) return { 0, hs_err };
            // TODO: it is possible that handshake size > net_record_data_size
            // that means, more net records must be read and concatenated
            break;
        }
        case ContentType::APPLICATION_DATA:
            break;
    }
    return { sizeof(TlsPlaintext) + record_data_size, {} };
}

template<typename Hook>
ParserError Parser::parse_alert( Hook* hook, const uint8_t* buffer, uint32_t buffer_size )
{
    auto* alert = reinterpret_cast<const Alert*>( buffer );
    if( sizeof( Alert ) > buffer_size )
        return ParserError( ParserErrno::E_ALERT_NO_SPACE );

    hook->tls_alert( *alert );

    return {};
}

template<typename Hook>
ParserError Parser::parse_handshake( Hook* hook
        ,const uint8_t* buffer, uint32_t buffer_size )
{
    uint32_t handshake_data_size;
    const uint8_t* handshake_data;
    if( !parse_vec24( buffer, buffer_size, handshake_data, handshake_data_size
                      ,sizeof(HandshakeType) ) )
    {
        return ParserError( ParserErrno::W_LOW_DATA_IN_HANDSHAKE );
    }

    auto* handshake = reinterpret_cast<const Handshake*>( buffer );
    hook->tls_handshake( handshake );

    switch( handshake->msg_type )
    {
        case HandshakeType::CLIENT_HELLO:
            return parse_client_hello_message<Hook>( hook, handshake_data, handshake_data_size );
        case HandshakeType::SERVER_HELLO:
            return parse_server_hello_message<Hook>( hook, handshake_data, handshake_data_size );
        case HandshakeType::NEW_SESSION_TICKET:
        case HandshakeType::END_OF_EARLY_DATA:
        case HandshakeType::ENCRYPTED_EXTENSIONS:
            return parse_encrypted_extensions<Hook>( hook
                    ,handshake_data, handshake_data_size, HandshakeType::ENCRYPTED_EXTENSIONS );
        case HandshakeType::CERTIFICATE:
            return parse_certificate<Hook>( hook, handshake_data, handshake_data_size );
        case HandshakeType::CERTIFICATE_REQUEST:
        case HandshakeType::CERTIFICATE_VERIFY:
            return parse_certificate_verify<Hook>( hook, handshake_data, handshake_data_size );
        case HandshakeType::FINISHED:
            return parse_finished<Hook>( hook, handshake_data, handshake_data_size );
        case HandshakeType::KEY_UPDATE:
        case HandshakeType::MESSAGE_HASH:
            break;
    }
    return {};
}

/*
 * uint16 ProtocolVersion;
 * opaque Random[32];
 * uint8 CipherSuite[2];    // Cryptographic suite selector
 * struct {
 *     ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *     Random random;
 *     opaque legacy_session_id<0..32>;
 *     CipherSuite cipher_suites<2..2^16-2>;
 *     opaque legacy_compression_methods<1..2^8-1>;
 *     Extension extensions<8..2^16-1>;
 * } ClientHello;
 */
template<typename Hook>
ParserError Parser::parse_client_hello_message( Hook* hook
        ,const uint8_t* buffer, uint32_t buffer_size )
{
    if( sizeof(ClientHello) > buffer_size )
        return ParserError(ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_VERSION_OR_RANDOM );

    auto* client_hello = reinterpret_cast<const ClientHello*>(buffer);
    auto* legacy_protocol_version = &(client_hello->legacy_version);
    const auto random = &client_hello->random;
    uint32_t offset = sizeof(ClientHello);

    uint8_t legacy_session_id_size;
    const uint8_t* unused_data;
    if( !parse_vec8( buffer+offset, buffer_size-offset
            ,unused_data, legacy_session_id_size ) )
    {
        return ParserError( ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_LEGACY_SESSION_ID );
    }
    const auto* legacy_session_id = reinterpret_cast<const LegacySessionId*>( buffer + offset );
    offset += (sizeof(uint8_t)+legacy_session_id_size);

    uint16_t cipher_suites_size;
    const CipherSuite* cipher_suites_data;
    if( !parse_vec16( buffer+offset, buffer_size-offset
                     , reinterpret_cast<const uint8_t*&>(cipher_suites_data), cipher_suites_size ) )
    {
        return ParserError( ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_CIPHER_SUITES );
    }
    offset += (sizeof(uint16_t)+cipher_suites_size);

    uint8_t legacy_compression_methods_size;
    const uint8_t* legacy_compression_methods_data;
    if( !parse_vec8( buffer+offset, buffer_size-offset
                      ,legacy_compression_methods_data, legacy_compression_methods_size ) )
    {
        return ParserError( ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_LEGACY_COMPRESSION_METHODS );
    }
    offset += (sizeof(uint8_t)+legacy_compression_methods_size);

    uint16_t extensions_data_size;
    const uint8_t* extensions_data;
    if( !parse_vec16( buffer+offset, buffer_size-offset
                      ,extensions_data, extensions_data_size ) )
    {
        return ParserError( ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_EXTENSIONS );
    }

    hook->client_hello_protocol_version( legacy_protocol_version );
    hook->client_hello_random( random );
    hook->client_hello_legacy_session_id( legacy_session_id );
    hook->client_hello_cipher_suites( cipher_suites_data, cipher_suites_size );
    hook->client_hello_legacy_compression_methods(
            legacy_compression_methods_data, legacy_compression_methods_size );

    hook->extensions_list( extensions_data_size );
    auto err = parse_extensions<Hook>( hook, extensions_data, extensions_data_size
            ,HandshakeType::CLIENT_HELLO );

    return err;
}

/*
 * struct {
 *     ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *     Random random;
 *     opaque legacy_session_id_echo<0..32>;
 *     CipherSuite cipher_suite;
 *     uint8 legacy_compression_method = 0;
 *     Extension extensions<6..2^16-1>;
 * } ServerHello;
 */
template<typename Hook>
ParserError Parser::parse_server_hello_message( Hook* hook
        ,const uint8_t* buffer, uint32_t buffer_size )
{
    if( sizeof(ClientHello) > buffer_size )
        return ParserError(ParserErrno::E_SERVER_HELLO_NO_SPACE_FOR_VERSION_OR_RANDOM );

    auto* server_hello = reinterpret_cast<const ServerHello*>(buffer);
    auto* legacy_version = &(server_hello->legacy_version);
    const auto random = &server_hello->random;
    uint32_t offset = sizeof(ServerHello);

    uint8_t legacy_session_id_size;
    const uint8_t* unused_data;
    if( !parse_vec8( buffer+offset, buffer_size-offset
                     ,unused_data, legacy_session_id_size ) )
    {
        return ParserError( ParserErrno::E_SERVER_HELLO_NO_SPACE_FOR_LEGACY_SESSION_ID_ECHO );
    }
    const auto* legacy_session_id_echo = reinterpret_cast<const LegacySessionId*>( buffer + offset );
    offset += (sizeof(uint8_t)+legacy_session_id_size);

    if( (offset+sizeof(CipherSuite) ) > buffer_size )
        return ParserError(ParserErrno::E_SERVER_HELLO_NO_SPACE_FOR_CIPHER_SUITE );
    uint16_t cipher_suites_size = sizeof(CipherSuite);
    const auto* cipher_suite = reinterpret_cast<const CipherSuite*>( buffer + offset );
    offset += cipher_suites_size;
    if( offset > buffer_size )
        return ParserError(ParserErrno::E_SERVER_HELLO_NO_SPACE_FOR_CIPHER_SUITE );

    // uint8 legacy_compression_method = 0;
    if( (offset+1) > buffer_size )
        return ParserError(ParserErrno::E_SERVER_HELLO_NO_SPACE_FOR_LEGACY_COMPRESSION_METHOD );
    uint8_t legacy_compression_methods_size = 1;
    const auto* legacy_compression_methods_data = (buffer + offset);
    offset += legacy_compression_methods_size;

    // Extension extensions<6..2^16-1>;
    uint16_t extensions_data_size;
    const uint8_t* extensions_data;
    if( !parse_vec16( buffer+offset, buffer_size-offset
                      ,extensions_data, extensions_data_size ) )
    {
        return ParserError( ParserErrno::E_SERVER_HELLO_NO_SPACE_FOR_EXTENSIONS );
    }

    hook->server_hello_protocol_version( legacy_version );
    hook->server_hello_random( random );
    hook->server_hello_legacy_session_id( legacy_session_id_echo );
    hook->server_hello_cipher_suites( cipher_suite, cipher_suites_size );
    hook->server_hello_legacy_compression_methods(
            legacy_compression_methods_data, legacy_compression_methods_size );

    hook->extensions_list( extensions_data_size );
    auto err = parse_extensions<Hook>( hook, extensions_data, extensions_data_size
            ,HandshakeType::SERVER_HELLO );

    return err;
}
template<typename Hook>
ParserError Parser::parse_encrypted_extensions( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size
        ,HandshakeType handshake_type )
{
    /*
     * struct {
     *     Extension extensions<0..2^16-1>;
     * } EncryptedExtensions;
     */
    uint16_t extensions_data_size;
    const uint8_t* extensions_data;
    if( !parse_vec16( buffer, buffer_size,extensions_data, extensions_data_size ) )
    {
        return ParserError(ParserErrno::E_ENCRYPTED_EXTENSIONS_NO_SPACE_FOR_ENCRYPTED_EXTENSIONS);
    }

    return parse_extensions<Hook>( hook, extensions_data, extensions_data_size, handshake_type );
}

template<typename Hook>
ParserError Parser::parse_certificate( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size )
{
    /*
     * struct {
     *     opaque certificate_request_context<0..2^8-1>;
     *     CertificateEntry certificate_list<0..2^24-1>;
     * } Certificate;
     */
    uint8_t certificate_request_context_size;
    const uint8_t* certificate_request_context_data;
    if( !parse_vec8( buffer, buffer_size
            ,certificate_request_context_data, certificate_request_context_size ) )
    {
        return ParserError(ParserErrno::E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_REQUEST_CONTEXT);
    }

    buffer += (sizeof(uint8_t)+certificate_request_context_size);
    buffer_size -= (sizeof(uint8_t)+certificate_request_context_size);

    // CertificateEntry certificate_list<0..2^24-1>;
    uint32_t certificate_list_size;
    const uint8_t* certificate_list_data;
    if( !parse_vec24( buffer, buffer_size, certificate_list_data, certificate_list_size ) )
    {
        return ParserError(ParserErrno::E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_LIST);
    }

    hook->certificate_request_context( certificate_request_context_data, certificate_request_context_size );
    hook->certificate_list( certificate_list_size );

    return parse_certificate_entry<Hook>( hook, certificate_list_data, certificate_list_size );
}

template<typename Hook>
ParserError Parser::parse_certificate_verify( Hook* hook, const uint8_t* buffer, uint16_t buffer_size )
{
    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    uint16_t signature_size;
    const uint8_t* signature_data;
    if( !parse_vec16( buffer, buffer_size
            ,signature_data, signature_size, sizeof(SignatureScheme) ) )
    {
        return ParserError(ParserErrno::E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_VERIFY);
    }
    auto* cert_verify = reinterpret_cast<const CertificateVerify*>(buffer);

    hook->cert_verify_data( &cert_verify->algorithm, signature_data, signature_size );

    return ParserError();
}
template<typename Hook>
ParserError Parser::parse_finished( Hook* hook, const uint8_t* buffer, uint16_t buffer_size )
{
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    hook->finished_data( buffer, buffer_size );

    return ParserError();
}


template<typename Hook>
ParserError Parser::parse_certificate_entry( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size, CertificateType cert_type )
{
    /*
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
    /*
     * If the corresponding certificate type extension
     * ("server_certificate_type" or "client_certificate_type") was not
     * negotiated in EncryptedExtensions, or the X.509 certificate type was
     * negotiated, then each CertificateEntry contains a DER-encoded X.509
     * certificate.
     */
    while( buffer_size > 0 )
    {   // will parse X509 // opaque cert_data<1..2^24-1>;
        uint32_t cert_data_size;
        const uint8_t* cert_data;
        if( !parse_vec24( buffer, buffer_size, cert_data, cert_data_size ) )
            return ParserError(ParserErrno::E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_ENTRY );

        buffer += ( sizeof(NetUint24)+cert_data_size );
        buffer_size -= ( sizeof(NetUint24)+cert_data_size );

        // Extension extensions<0..2^16-1>;
        uint16_t extensions_data_size;
        const uint8_t* extensions_data;
        if( !parse_vec16( buffer, buffer_size, extensions_data, extensions_data_size ) )
            return ParserError(ParserErrno::E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_EXTENSIONS );

        buffer += ( sizeof(uint16_t) + extensions_data_size );
        buffer_size -= ( sizeof(uint16_t) + extensions_data_size );

        hook->cert_data( cert_type, cert_data, cert_data_size );
        hook->extensions_list( extensions_data_size );
        auto err = parse_extensions<Hook>( hook, extensions_data, extensions_data_size
                                           ,HandshakeType::SERVER_HELLO );
        if( err )
            return err;
    }

    return ParserError();
}


template<typename Hook>
ParserError Parser::parse_extensions( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size
        ,HandshakeType handshake_type )
{
    /*
     * struct {
     *     ExtensionType m_extension_type;
     *     opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    while( true )
    {
        uint16_t extension_data_size;
        const uint8_t* extension_internal_data;
        if( !parse_vec16( buffer, buffer_size, extension_internal_data, extension_data_size
                          ,sizeof(uint16_t) ) )
        {
            break;
        }
        const auto* extension = reinterpret_cast<const Extension*>( buffer );

        buffer += (sizeof(uint16_t)+sizeof(uint16_t)+extension_data_size);
        buffer_size -= (sizeof(uint16_t)+sizeof(uint16_t)+extension_data_size);

        hook->extension( extension->extension_type(), extension_data_size );
        switch( extension->extension_type() )
        {
            case ExtensionType::SERVER_NAME:
            {
                auto err = parse_extension_server_name<Hook>( hook
                        ,extension_internal_data, extension_data_size );
                if( err ) return err;
                break;
            }
            case ExtensionType::MAX_FRAGMENT_LENGTH:
            case ExtensionType::STATUS_REQUEST:
                break;
            case ExtensionType::SUPPORTED_GROUPS:
            {
                auto err = parse_extension_supported_groups<Hook>(
                        hook, extension_internal_data, extension_data_size );
                if( err ) return err;
                break;
            }
            case ExtensionType::SIGNATURE_ALGORITHMS:
            {
                auto err = parse_extension_signature_algorithms<Hook>(
                        hook, extension_internal_data, extension_data_size );
                if( err ) return err;
                break;
            }
            case ExtensionType::USE_SRTP:
            case ExtensionType::HEARTBEAT:
            case ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            case ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP:
            case ExtensionType::CLIENT_CERTIFICATE_TYPE:
            case ExtensionType::SERVER_CERTIFICATE_TYPE:
            case ExtensionType::PADDING:
            case ExtensionType::PRE_SHARED_KEY:
            case ExtensionType::EARLY_DATA:
                break;
            case ExtensionType::SUPPORTED_VERSIONS:
            {
                auto err = parse_extension_supported_versions<Hook>( hook
                        ,extension_internal_data, extension_data_size, handshake_type );
                if( err ) return err;
                break;
            }
            case ExtensionType::COOKIE:
                break;
            case ExtensionType::PSK_KEY_EXCHANGE_MODES:
            {
                auto err = parse_extension_psk_key_exchange_modes<Hook>( hook
                        ,extension_internal_data, extension_data_size );
                if( err ) return err;
                break;
            }
            case ExtensionType::CERTIFICATE_AUTHORITIES:
            case ExtensionType::OID_FILTERS:
            case ExtensionType::POST_HANDSHAKE_AUTH:
            case ExtensionType::SIGNATURE_ALGORITHMS_CERT:
                break;
            case ExtensionType::KEY_SHARE:
            {
                auto err = parse_extension_key_share<Hook>( hook
                        ,extension_internal_data, extension_data_size, handshake_type );
                if( err ) return err;
                break;
            }
            default:
                break;
        }
    }

    return ParserError();
}
template<typename Hook>
ParserError Parser::parse_extension_server_name( Hook* hook
        ,const uint8_t* extensions_internal_data, uint16_t extensions_data_size )
{
    /*
     * struct {
     *     NameType name_type;
     *     select (name_type) {
     *         case host_name: HostName;
     *     } name;
     * } ServerName;
     * enum {
     *     host_name(0), (255)
     * } NameType;
     * opaque HostName<1..2^16-1>;
     * struct {
     *     ServerName server_name_list<1..2^16-1>
     * } ServerNameList;
     */
    // extensions_internal_data points to ServerNameList

    if(( sizeof(ServerNameList) + sizeof( NameType ) + sizeof( HostName ) ) > extensions_data_size )
        return ParserError( ParserErrno::E_EXTENSION_SERVER_NAME_NO_SPACE );

    const auto* server_name_list = reinterpret_cast<const ServerNameList*>(extensions_internal_data);
    uint16_t server_name_list_size = server_name_list->size();

    if( (sizeof(ServerNameList)+server_name_list_size) > extensions_data_size )
        return ParserError( ParserErrno::E_EXTENSION_SERVER_NAME_NO_SPACE );

    const auto* server_name = reinterpret_cast<const ServerName*>(
            extensions_internal_data+sizeof(ServerNameList) );
    if( server_name->name_type != NameType::HOST_NAME )
        return ParserError( ParserErrno::E_EXTENSION_SERVER_NAME_UNKNOWN_TYPE );

    const auto* host_name = reinterpret_cast<const HostName*>(
            extensions_internal_data + sizeof(ServerNameList)+sizeof(ServerName) );
    uint16_t host_name_size = host_name->host_size();

    if( (sizeof(ServerNameList)+sizeof( NameType ) + sizeof( HostName ) + host_name_size)
        > extensions_data_size )
        return ParserError( ParserErrno::E_EXTENSION_SERVER_NAME_NO_SPACE );

    const auto* host_name_data = extensions_internal_data
            + sizeof(ServerNameList) + sizeof( NameType ) + sizeof( HostName );

    hook->extension_server_name( server_name->name_type, host_name_data, host_name_size );

    return ParserError();
}

template< typename Hook >
ParserError Parser::parse_extension_supported_versions( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size
        ,HandshakeType handshake_type )
{
    /*
     * struct {
     *     select (Handshake.msg_type) {
     *         case client_hello:
     *              ProtocolVersion versions<2..254>;
     *         case server_hello: // and HelloRetryRequest
     *              ProtocolVersion selected_version;
     *     };
     * } SupportedVersions;
     */

    switch( handshake_type )
    {
        case HandshakeType::CLIENT_HELLO:
        {
            uint8_t protocol_size;
            const ProtocolVersion* protocol_version;
            if( !parse_vec8( buffer, buffer_size
                    ,reinterpret_cast<const uint8_t*&>(protocol_version), protocol_size) )
            {
                return ParserError( ParserErrno::E_SUPPORTED_VERSIONS_NO_SPACE );
            }

            for( unsigned i = 0; i < protocol_size/sizeof(ProtocolVersion); ++i )
                hook->extension_supported_version( protocol_version[i] );
            break;
        }
        default:
        {
            const auto* protocol_version = reinterpret_cast<const ProtocolVersion*>(buffer);
            if( sizeof(ProtocolVersion) > buffer_size )
                return ParserError( ParserErrno::E_SUPPORTED_VERSIONS_NO_SPACE );
            hook->extension_supported_version( *protocol_version );
            break;
        }
    }

    return ParserError();
}

template< typename Hook >
ParserError Parser::parse_extension_key_share( Hook* hook, const uint8_t* buffer, uint16_t buffer_size
        ,HandshakeType handshake_type )
{
    /*
     * struct {
     *     KeyShareEntry client_shares<0..2^16-1>;
     * } KeyShareClientHello;
     * struct {
     *     KeyShareEntry server_share;
     * } KeyShareServerHello;
     */
    const KeyShareEntry* key_share_entry = nullptr;
    uint16_t key_share_entry_size = 0;
    switch( handshake_type )
    {
        case HandshakeType::CLIENT_HELLO:
        {
            if( !parse_vec16( buffer, buffer_size
                             ,reinterpret_cast<const uint8_t*&>(key_share_entry)
                             ,key_share_entry_size) )
            {
                return ParserError( ParserErrno::E_EXTENSION_KEY_SHARE_NO_SPACE );
            }
            break;
        }
        case HandshakeType::SERVER_HELLO:
        {
            key_share_entry = reinterpret_cast<const KeyShareEntry*>( buffer );
            key_share_entry_size = buffer_size;
            break;
        }
        default:
            throw std::runtime_error( "Parser::parse_extension_key_share got unknown handshake type"
                                      +std::to_string(static_cast<uint8_t>(handshake_type)) );
    }
    /*
     * struct {
     *     NamedGroup group;
     *     opaque key_exchange<1..2^16-1>;
     * } KeyShareEntry;
     */
    while( key_share_entry_size > 0 )
    {
        const uint8_t* key_data;
        uint16_t key_size;
        if( !parse_vec16( key_share_entry, key_share_entry_size
                ,key_data, key_size, sizeof(NamedGroup) ) )
        {
            return ParserError( ParserErrno::E_EXTENSION_KEY_SHARE_NO_SPACE );
        }

        NamedGroup named_group = ntoh_named_group( key_share_entry->group );

        hook->key_share_entry( named_group, key_data, key_size );

        key_share_entry = reinterpret_cast<const KeyShareEntry*>(key_data + key_size);
        key_share_entry_size -= (sizeof(KeyShareEntry) + key_size);
    }

    return ParserError();
}

template< typename Hook >
ParserError Parser::parse_extension_supported_groups( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size )
{
    /*
     * NamedGroup is 2 bytes enum
     * struct {
     *     NamedGroup named_group_list<2..2^16-1>;
     * } NamedGroupList;
     */
    const NamedGroup* named_group;
    uint16_t named_group_list_size;
    if( !parse_vec16( buffer, buffer_size, (const uint8_t*&)named_group, named_group_list_size ) )
    {
        return ParserError( ParserErrno::E_EXTENSION_SUPPORTED_GROUPS_NO_SPACE );
    }

    for( unsigned i = 0; i < named_group_list_size/sizeof(NamedGroup); ++i)
    {
        hook->named_group( ntoh_named_group(named_group[i]) );
    }

    return ParserError();
}
template< typename Hook >
ParserError Parser::parse_extension_signature_algorithms( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size )
{
    /*
     * SignatureScheme is 2 bytes enum
     * struct {
     *     SignatureScheme supported_signature_algorithms<2..2^16-2>;
     * } SignatureSchemeList;
     */
    const SignatureScheme* signature_scheme;
    uint16_t signature_scheme_list_size;
    if( !parse_vec16( buffer, buffer_size, (const uint8_t*&)signature_scheme, signature_scheme_list_size ) )
    {
        return ParserError( ParserErrno::E_EXTENSION_SIGNATURE_ALGORITHMS_NO_SPACE );
    }

    for( unsigned i = 0; i < signature_scheme_list_size/sizeof(SignatureScheme); ++i)
    {
        hook->signature_scheme( signature_scheme[i] );
    }

    return ParserError();
}
template<typename Hook>
ParserError Parser::parse_extension_psk_key_exchange_modes( Hook* hook
        ,const uint8_t* buffer, uint16_t buffer_size )
{
    /*
     * enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
     * struct {
     *     PskKeyExchangeMode ke_modes<1..255>;
     * } PskKeyExchangeModes;
     */
    const PskKeyExchangeMode* psk_key_exchange_mode;
    uint8_t psk_key_exchange_modes_size;
    if( !parse_vec8( buffer, buffer_size
            ,(const uint8_t*&)psk_key_exchange_mode, psk_key_exchange_modes_size ) )
    {
        return ParserError( ParserErrno::E_EXTENSION_KEY_EXCHANGE_MODES_NO_SPACE );
    }

    for( unsigned i = 0; i < psk_key_exchange_modes_size/sizeof(PskKeyExchangeMode); ++i)
    {
        hook->psk_key_exchange_mode( psk_key_exchange_mode[i] );
    }

    return ParserError();
}

inline uint32_t full_record_size( const uint8_t* buffer )
{
    const auto* tls_record = reinterpret_cast<const TLSCiphertext*>( buffer );
    return tls_record->length() + sizeof(TLSCiphertext);
}
inline const uint8_t* record_content_data( const uint8_t* buffer )
{
    return buffer + sizeof(TlsPlaintext);
}
inline uint8_t* record_content_data( uint8_t* buffer )
{
    return buffer + sizeof(TlsPlaintext);
}
inline ContentType record_content_type( const uint8_t* buffer )
{
    const auto* tls_record = reinterpret_cast<const TLSCiphertext*>( buffer );
    return tls_record->opaque_type;
}
inline uint16_t record_content_size( const uint8_t* buffer )
{
    const auto* tls_record = reinterpret_cast<const TLSCiphertext*>( buffer );
    return tls_record->length();
}

inline bool is_handshake_record( const uint8_t* buffer )
{
    const auto* tls_record = reinterpret_cast<const TLSCiphertext*>( buffer );
    return tls_record->opaque_type == ContentType::HANDSHAKE;
}
inline HandshakeType record_handshake_type( const uint8_t* buffer )
{
    const auto* handshake_message = reinterpret_cast<const Handshake*>(
            buffer + sizeof(TlsPlaintext) );
    return handshake_message->msg_type;
}
inline const uint8_t* handshake_message( const uint8_t* buffer )
{
    const auto* handshake_message = buffer + sizeof(TlsPlaintext);
    return handshake_message;
}

}
