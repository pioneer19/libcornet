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

#include <libcornet/tls/parser.hpp>

#include <endian.h>

#include <openssl/x509.h>
#include <openssl/err.h>

#include <cstdio>
#include <charconv>
#include <iostream>

#include <libcornet/tls/types.hpp>

namespace pioneer19::cornet::tls13::record
{

struct PrintHook
{
    static void tls_plaintext( const TlsPlaintext* tls_plaintext );
    static void tls_handshake( const Handshake* handshake );
    static void client_hello_protocol_version( const ProtocolVersion* protocol_version );
    static void client_hello_random( const Random* random );
    static void client_hello_legacy_session_id( const LegacySessionId* );
    static void client_hello_cipher_suites( const CipherSuite*, uint32_t );
    static void client_hello_legacy_compression_methods(const uint8_t* methods_data, uint8_t size_in_bytes);
    static void server_hello_protocol_version( const ProtocolVersion* );
    static void server_hello_random( const Random* );
    static void server_hello_legacy_session_id( const LegacySessionId* );
    static void server_hello_cipher_suites( const CipherSuite*, uint32_t );
    static void server_hello_legacy_compression_methods( const uint8_t*, uint8_t );
    static void extensions_list( uint16_t );
    static void extension( ExtensionType extension_type, uint16_t size_in_bytes );
    static void extension_server_name( NameType, const uint8_t*, uint16_t );
    static void extension_supported_version( ProtocolVersion protocol_version );
    static void named_group( NamedGroup );
    static void signature_scheme( SignatureScheme );
    static void psk_key_exchange_mode( PskKeyExchangeMode );
    static void key_share_entry( NamedGroup, const uint8_t*, uint16_t );
    static void certificate_request_context( const uint8_t* certificate_request_context_data
            , uint32_t certificate_request_context_size );
    static void certificate_list( uint32_t certificate_list_size );
    static void cert_data(  CertificateType cert_type, const uint8_t* cert_data, uint32_t cert_size );
    static void cert_verify_data( const SignatureScheme*, const uint8_t*, uint32_t );
    static void finished_data( const uint8_t*, uint32_t );
    static void tls_alert( const Alert );
};

static char hex_char( char c )
{
    if( c < 0xA )
        return '0'+c;
    else
        return 'a'-10+c;
}

static std::string hex_byte( char c )
{
    std::string res;
    auto byte = static_cast<uint8_t>(c);
    res += hex_char(byte >> 4);
    res += hex_char(byte & 0x0F);

    return res;
}
static std::string hex_string( const uint8_t* buff, size_t size ) noexcept
{
    std::string res;
    if( size == 0 )
        return res;

    res += hex_byte( buff[0] );
    for( size_t i = 1; i < size; ++i )
    {
        res += " ";
        res += hex_byte(buff[i]);
    }
    return res;
}
template<typename T>
std::string hex_number( T int_value )
{
    char buff[sizeof(T)*2+1];
    auto conv_res = std::to_chars( buff, buff+sizeof(buff), int_value, 16 );
    if( conv_res.ec != std::errc() )
        throw std::system_error( static_cast<uint32_t>(conv_res.ec)
                                 ,std::system_category(), "failed std::to_chars" );

    *(conv_res.ptr) = 0;
    return buff;
}

static std::string content_type_string( ContentType type )
{
    switch( type )
    {
        case ContentType::INVALID:
            return "invalid(0)";
        case ContentType::CHANGE_CIPHER_SPEC:
            return "change_cipher_spec(20)";
        case ContentType::ALERT:
            return "alert(21)";
        case ContentType::HANDSHAKE:
            return "handshake(22)";
        case ContentType::APPLICATION_DATA:
            return "application_data(23)";
        default:
            return std::string("unknown(") + std::to_string(static_cast<uint8_t>(type)) + ")";
    }
}

static std::string protocol_version_string( ProtocolVersion version )
{
    switch( version.num() )
    {
        case PROTOCOL_VERSION_TLS10.num():
            return "TLSv1.0(0x0301)";
        case PROTOCOL_VERSION_TLS12.num():
            return "TLSv1.2(0x0303)";
        case PROTOCOL_VERSION_TLS13.num():
            return "TLSv1.3(0x0304)";
        default:
            return std::string("unknown(0x") + hex_string(version.v_data, 2) + ")";
    }
}

static std::string handshake_type_string( HandshakeType msg_type )
{
    switch( msg_type )
    {
        case HandshakeType::CLIENT_HELLO:
            return "client_hello(1)";
        case HandshakeType::SERVER_HELLO:
            return "server_hello(2)";
        case HandshakeType::NEW_SESSION_TICKET:
            return "new_session_ticket(4)";
        case HandshakeType::END_OF_EARLY_DATA:
            return "end_of_early_data(5)";
        case HandshakeType::ENCRYPTED_EXTENSIONS:
            return "encrypted_extensions(8)";
        case HandshakeType::CERTIFICATE:
            return "certificate(11)";
        case HandshakeType::CERTIFICATE_REQUEST:
            return "certificate_request(13)";
        case HandshakeType::CERTIFICATE_VERIFY:
            return "certificate_verify(15)";
        case HandshakeType::FINISHED:
            return "finished(20)";
        case HandshakeType::KEY_UPDATE:
            return "key_update(24)";
        case HandshakeType::MESSAGE_HASH:
            return "message_hash(254)";
        default:
            return std::string("unknown")+std::to_string(static_cast<uint32_t>(msg_type));
    }
}

static std::string cipher_suite_string( CipherSuite cipher )
{
    switch( cipher.num() )
    {
        case TLS_AES_128_GCM_SHA256.num():
            return "TLS_AES_128_GCM_SHA256";
        case TLS_AES_256_GCM_SHA384.num():
            return "TLS_AES_256_GCM_SHA384";
        case TLS_CHACHA20_POLY1305_SHA256.num():
            return "TLS_CHACHA20_POLY1305_SHA256";
        case TLS_AES_128_CCM_SHA256.num():
            return "TLS_AES_128_CCM_SHA256";
        case TLS_AES_128_CCM_8_SHA256.num():
            return "TLS_AES_128_CCM_8_SHA256";
        default:
            return std::string("unknown(0x") + hex_string(cipher.cipher, 2) + ")";
    }
}

static std::string extension_type_string( ExtensionType type )
{
    switch( type )
    {
        case ExtensionType::SERVER_NAME:
            return "server_name(0)";
        case ExtensionType::MAX_FRAGMENT_LENGTH:
            return "max_fragment_length(1)";
        case ExtensionType::STATUS_REQUEST:
            return "status_request(5)";
        case ExtensionType::SUPPORTED_GROUPS:
            return "supported_groups(10)";
        case ExtensionType::SIGNATURE_ALGORITHMS:
            return "signature_algorithms(13)";
        case ExtensionType::USE_SRTP:
            return "use_srtp(14)";
        case ExtensionType::HEARTBEAT:
            return "heartbeat(15)";
        case ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            return "application_layer_protocol_negotiation(16)";
        case ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP:
            return "signed_certificate_timestamp(18)";
        case ExtensionType::CLIENT_CERTIFICATE_TYPE:
            return "client_certificate_type(19)";
        case ExtensionType::SERVER_CERTIFICATE_TYPE:
            return "server_certificate_type(20)";
        case ExtensionType::PADDING:
            return "padding(21)";
        case ExtensionType::PRE_SHARED_KEY:
            return "pre_shared_key(41)";
        case ExtensionType::EARLY_DATA:
            return "early_data(42)";
        case ExtensionType::SUPPORTED_VERSIONS:
            return "supported_versions(43)";
        case ExtensionType::COOKIE:
            return "cookie(44)";
        case ExtensionType::PSK_KEY_EXCHANGE_MODES:
            return "psk_key_exchange_modes(45)";
        case ExtensionType::CERTIFICATE_AUTHORITIES:
            return "certificate_authorities(47)";
        case ExtensionType::OID_FILTERS:
            return "oid_filters(48)";
        case ExtensionType::POST_HANDSHAKE_AUTH:
            return "post_handshake_auth(49)";
        case ExtensionType::SIGNATURE_ALGORITHMS_CERT:
            return "signature_algorithms_cert(50)";
        case ExtensionType::KEY_SHARE:
            return "key_share(51)";
        default:
            return std::string("unsupported_extension(")
                   +std::to_string( static_cast<uint16_t>(type) ) + ")";
    }
}

void PrintHook::tls_plaintext( const TlsPlaintext* tls_plaintext )
{
    std::cout << "TLS record:"
              << " content_type " << content_type_string( tls_plaintext->type )
              << " legacy_record_version "
              << protocol_version_string( tls_plaintext->legacy_record_version )
              << " length 0x" << hex_number( tls_plaintext->host_length() )
              << "\n";
}

void PrintHook::tls_handshake( const Handshake* handshake )
{
    std::cout << "Handshake:"
              << " msg_type " << handshake_type_string( handshake->msg_type )
              << " length 0x" << hex_number( handshake->host_length() )
              << "\n";
}

void PrintHook::client_hello_protocol_version( const ProtocolVersion* protocol_version )
{
    std::cout << "ClientHello:"
              << " legacy_version " << protocol_version_string( *protocol_version );
}

void PrintHook::server_hello_protocol_version( const ProtocolVersion* protocol_version )
{
    std::cout << "ServerHello:"
              << " legacy_version " << protocol_version_string( *protocol_version );
}

void PrintHook::client_hello_random( const Random* random )
{
    std::cout << " random " << hex_string( random->data(), random->size() ) << "\n";
}

void PrintHook::server_hello_random( const Random* random )
{
    std::cout << " random " << hex_string( random->data(), random->size() ) << "\n";
}

void PrintHook::client_hello_legacy_session_id( const LegacySessionId* session_id )
{
    std::cout << "legacy_session_id(0x" << hex_number(session_id->size) << ")";
    if( session_id->size != 0 )
    {
        std::cout << " " << hex_string( reinterpret_cast<const uint8_t*>(session_id) + 1
                                        , session_id->size );
    }
    std::cout << "\n";
}

void PrintHook::server_hello_legacy_session_id( const LegacySessionId* session_id_echo )
{
    std::cout << "legacy_session_id(0x" << hex_number( session_id_echo->size) << ")";
    if( session_id_echo->size != 0 )
    {
        std::cout << " " << hex_string( reinterpret_cast<const uint8_t*>(session_id_echo) + 1
                                        , session_id_echo->size );
    }
    std::cout << "\n";
}

void PrintHook::client_hello_cipher_suites( const CipherSuite* cipher_suite, uint32_t size_in_bytes )
{
    std::cout << "  cipher_suites size 0x" << hex_number( size_in_bytes ) << ":\n";
    for( uint32_t idx = 0; idx < size_in_bytes/sizeof(CipherSuite); ++idx)
    {
        std::cout << "    " << cipher_suite_string( cipher_suite[idx] ) << "\n";
    }
}

void PrintHook::server_hello_cipher_suites( const CipherSuite* cipher_suite, uint32_t )
{
    std::cout << "    " << cipher_suite_string( *cipher_suite ) << "\n";
}

void PrintHook::client_hello_legacy_compression_methods( const uint8_t* methods_data, uint8_t size_in_bytes )
{
    std::cout << "legacy_compression_methods size 0x" << hex_number( size_in_bytes );
    if( size_in_bytes != 0 )
        std::cout << " " << hex_string( methods_data, size_in_bytes );

    std::cout << "\n";
}

void PrintHook::server_hello_legacy_compression_methods( const uint8_t* method_data, uint8_t )
{
    std::cout << "legacy_compression_method "
              << hex_string( method_data, 1 ) << "\n";
}

void PrintHook::extensions_list( uint16_t size_in_bytes )
{
    std::cout << "extensions(size 0x" << hex_number(size_in_bytes) << ")\n";
}

void PrintHook::extension( ExtensionType extension_type, uint16_t size_in_bytes )
{
    std::cout << "    " << extension_type_string( extension_type )
              << " size " << size_in_bytes << "\n";
}

void PrintHook::extension_server_name( NameType, const uint8_t* hostname, uint16_t hostname_size )
{
    std::cout << "        host_name size " << hostname_size << " "
              << std::string( reinterpret_cast<const char*>(hostname), hostname_size) << "\n";
}

void PrintHook::extension_supported_version( ProtocolVersion protocol_version )
{
    std::cout << "        " << protocol_version_string( protocol_version ) << "\n";
}

static std::string named_group_string( NamedGroup named_group )
{
    switch( named_group )
    {
        /* Elliptic Curve Groups (ECDHE) */
        case NamedGroup::SECP256R1:
            return "secp256r1(0x0017)";
        case NamedGroup::SECP384R1:
            return "secp384r1(0x0018)";
        case NamedGroup::SECP521R1:
            return "secp521r1(0x0019)";
        case NamedGroup::X25519:
            return "x25519(0x001D)";
        case NamedGroup::X448:
            return "x448(0x001E)";
            /* Finite Field Groups (DHE) */
        case NamedGroup::FFDHE2048:
            return "ffdhe2048(0x0100)";
        case NamedGroup::FFDHE3072:
            return "ffdhe3072(0x0101)";
        case NamedGroup::FFDHE4096:
            return "ffdhe4096(0x0102)";
        case NamedGroup::FFDHE6144:
            return "ffdhe6144(0x0103)";
        case NamedGroup::FFDHE8192:
            return "ffdhe8192(0x0104)";
        default:
            return std::string("unknown(0x")
                   +hex_number( static_cast<uint16_t>(named_group))
                   +")";
    }
}

void PrintHook::named_group( NamedGroup named_group )
{
    std::cout << "        " << named_group_string( named_group ) << "\n";
}

static std::string signature_scheme_string( const SignatureScheme* signature_algo )
{
    switch( signature_algo->num() )
    {
        /* RSASSA-PKCS1-v1_5 algorithms */
        case SIGNATURE_SCHEME_RSA_PKCS1_SHA256.num():
            return "rsa_pkcs1_sha256(0x0401)";
        case SIGNATURE_SCHEME_RSA_PKCS1_SHA384.num():
            return "rsa_pkcs1_sha384(0x0501)";
        case SIGNATURE_SCHEME_RSA_PKCS1_SHA512.num():
            return "rsa_pkcs1_sha512(0x0601)";
            /* ECDSA algorithms */
        case SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256.num():
            return "ecdsa_secp256r1_sha256(0x0403)";
        case SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384.num():
            return "ecdsa_secp384r1_sha384(0x0503)";
        case SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512.num():
            return "ecdsa_secp521r1_sha512(0x0603)";
            /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        case SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256.num():
            return "rsa_pss_rsae_sha256(0x0804)";
        case SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384.num():
            return "rsa_pss_rsae_sha384(0x0805)";
        case SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512.num():
            return "rsa_pss_rsae_sha512(0x0806)";
            /* EdDSA algorithms */
        case SIGNATURE_SCHEME_ED25519.num():
            return "ed25519(0x0807)";
        case SIGNATURE_SCHEME_ED448.num():
            return "ed448(0x0808)";
            /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        case SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256.num():
            return "rsa_pss_pss_sha256(0x0809)";
        case SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384.num():
            return "rsa_pss_pss_sha384(0x080a)";
        case SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512.num():
            return "rsa_pss_pss_sha512(0x080b)";
            /* Legacy algorithms */
        case SIGNATURE_SCHEME_RSA_PKCS1_SHA1.num():
            return "rsa_pkcs1_sha1(0x0201)";
        case SIGNATURE_SCHEME_ECDSA_SHA1.num():
            return "ecdsa_sha1(0x0203)";
        default:
            return std::string("unknown(0x")
                   +hex_number( htobe16(static_cast<uint16_t>(signature_algo->num())) )
                   +")";
    }
}

void PrintHook::signature_scheme( SignatureScheme signature_scheme )
{
    std::cout << "        " << signature_scheme_string( &signature_scheme ) << "\n";
}

static std::string psk_key_exchange_mode_string( PskKeyExchangeMode mode )
{
    switch( mode )
    {
        case PskKeyExchangeMode::PSK_KE:
            return "psk_ke(0)";
        case PskKeyExchangeMode::PSK_DHE_KE:
            return "psk_dhe_ke(1)";
        default:
            return std::string("unknown(0x") +hex_number( static_cast<uint8_t>(mode) ) +")";
    }
}

void PrintHook::psk_key_exchange_mode( PskKeyExchangeMode psk_kex_mode )
{
    std::cout << "        " << psk_key_exchange_mode_string( psk_kex_mode ) << "\n";
}

void PrintHook::key_share_entry( NamedGroup named_group, const uint8_t* key_data, uint16_t key_size )
{
    std::cout << "        key_share_entry " << named_group_string( named_group )
              << " " << hex_string( key_data, key_size ) << "\n";

}

void PrintHook::certificate_request_context( const uint8_t* certificate_request_context_data,
                                             uint32_t certificate_request_context_size )
{
    std::cout << "    certificate_request_context size " << certificate_request_context_size
              << " data " << hex_string( certificate_request_context_data, certificate_request_context_size )
              << "\n";
}

void PrintHook::certificate_list( uint32_t certificate_list_size )
{
    std::cout << "    certificate_list size " << certificate_list_size << "\n";
}

static std::string certificate_type_string( CertificateType cert_type )
{
    switch( cert_type )
    {
        case CertificateType::X509:
            return "X509";
        case CertificateType::RawPublicKey:
            return "RawPublicKey";
        default:
            std::string("unknown(0x") + hex_number( static_cast<uint8_t>(cert_type) ) + ")";
    }
}
void PrintHook::cert_data( CertificateType cert_type, const uint8_t* cert_data, uint32_t cert_size )
{
    std::cout << "        cert_type " << certificate_type_string( cert_type )
              << " size " << cert_size << "\n";
    const uint8_t* in = cert_data;
    X509* x = d2i_X509( nullptr, &in, cert_size );
    if( x == nullptr )
        ERR_print_errors_fp(stderr);

    char buf[1024];
    X509_NAME* x509_name = X509_get_issuer_name(x);
    if( x509_name == nullptr )
        ERR_print_errors_fp(stderr);
    X509_NAME_oneline( x509_name, buf, sizeof(buf) );
    std::cout << "            issuer " << buf << "\n";

    x509_name = X509_get_subject_name(x);
    if( x509_name == nullptr )
        ERR_print_errors_fp(stderr);
    X509_NAME_oneline( x509_name, buf, sizeof(buf) );
    std::cout << "            subject " << buf << "\n";

    X509_free( x );
}

void PrintHook::cert_verify_data( const SignatureScheme* signature_scheme
        ,const uint8_t*, uint32_t buffer_size )
{
    std::cout << "        CertificateVerify " << signature_scheme_string( signature_scheme )
              << " size " << buffer_size << "\n";
}

void PrintHook::finished_data( const uint8_t*, uint32_t buffer_size )
{
    std::cout << "     finished verify_data["<< buffer_size << "]\n";
}

static std::string alert_level_string( AlertLevel level )
{
    switch( level )
    {
        case AlertLevel::WARNING:
            return "warning";
        case AlertLevel::FATAL:
            return "fatal";
        default:
            return std::string("unknown(") + std::to_string( static_cast<uint8_t>(level)) +")";
    }

}
static std::string alert_description_string( AlertDescription description )
{
    switch( description )
    {
        case AlertDescription::CLOSE_NOTIFY:
            return "close_notify(0)";
        case AlertDescription::UNEXPECTED_MESSAGE:
            return "unexpected_message(10)";
        case AlertDescription::BAD_RECORD_MAC:
            return "bad_record_mac(20)";
        case AlertDescription::RECORD_OVERFLOW:
            return "record_overflow(22)";
        case AlertDescription::HANDSHAKE_FAILURE:
            return "handshake_failure(40)";
        case AlertDescription::BAD_CERTIFICATE:
            return "bad_certificate(42)";
        case AlertDescription::UNSUPPORTED_CERTIFICATE:
            return "unsupported_certificate(43)";
        case AlertDescription::CERTIFICATE_REVOKED:
            return "certificate_revoked(44)";
        case AlertDescription::CERTIFICATE_EXPIRED:
            return "certificate_expired(45)";
        case AlertDescription::CERTIFICATE_UNKNOWN:
            return "certificate_unknown(46)";
        case AlertDescription::ILLEGAL_PARAMETER:
            return "illegal_parameter(47)";
        case AlertDescription::UNKNOWN_CA:
            return "unknown_ca(48)";
        case AlertDescription::ACCESS_DENIED:
            return "access_denied(49)";
        case AlertDescription::DECODE_ERROR:
            return "decode_error(50)";
        case AlertDescription::DECRYPT_ERROR:
            return "decrypt_error(51)";
        case AlertDescription::PROTOCOL_VERSION:
            return "protocol_version(70)";
        case AlertDescription::INSUFFICIENT_SECURITY:
            return "insufficient_security(71)";
        case AlertDescription::INTERNAL_ERROR:
            return "internal_error(80)";
        case AlertDescription::INAPPROPRIATE_FALLBACK:
            return "inappropriate_fallback(86)";
        case AlertDescription::USER_CANCELED:
            return "user_canceled(90)";
        case AlertDescription::MISSING_EXTENSION:
            return "missing_extension(109)";
        case AlertDescription::UNSUPPORTED_EXTENSION:
            return "unsupported_extension(110)";
        case AlertDescription::UNRECOGNIZED_NAME:
            return "unrecognized_name(112)";
        case AlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE:
            return "bad_certificate_status_response(113)";
        case AlertDescription::UNKNOWN_PSK_IDENTITY:
            return "unknown_psk_identity(115)";
        case AlertDescription::CERTIFICATE_REQUIRED:
            return "certificate_required(116)";
        case AlertDescription::NO_APPLICATION_PROTOCOL:
            return "no_application_protocol(120)";
        default:
            return std::string("unknown alert (") + std::to_string( static_cast<uint8_t>(description)) +")";
    }
}
void PrintHook::tls_alert( const Alert alert )
{
    std::cout << "    level=" << alert_level_string(alert.level)
              << " description: " << alert_description_string(alert.description) << "\n";
}

ParserError print_net_record( const uint8_t* buffer, uint32_t size )
{
    Parser parser;
    std::cout << "=== start record ===\n";
    auto [bytes_parsed,err] = parser.parse_net_record<PrintHook>( nullptr, buffer, size );
    std::cout << "=== end record ===\n";
    return err;
}

}
