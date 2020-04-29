/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tls/tls_acceptor_template.hpp>

#include <algorithm>

#include <libcornet/tls/parser.hpp>
#include <libcornet/tls/crypto/dhe_groups.hpp>
#include <libcornet/tls/crypto/record_ciphers.hpp>
#include <libcornet/tls/crypto/tls_handshake.hpp>
#include <libcornet/tls/tls_socket.hpp>
#include <libcornet/tls/record_helpers.hpp>

namespace pioneer19::cornet::tls13
{

struct ClientHelloHook : record::EmptyHook
{
    ClientHelloHook( crypto::TlsHandshake& tls_handshake
            ,record::LegacySessionId* legacy_session
    )
            : m_tls_handshake{tls_handshake}
              ,legacy_session_container{legacy_session}
    {}
    ~ClientHelloHook() = default;
    // hooks
    void client_hello_legacy_session_id( const record::LegacySessionId* legacy_session_id ) const;
    void client_hello_cipher_suites( const record::CipherSuite*, uint32_t );
    void extension_server_name( record::NameType, const uint8_t* name, uint16_t name_size )
    { m_tls_handshake.accept_sni->assign( reinterpret_cast<const char*>(name), name_size ); }
    void extension_supported_version( record::ProtocolVersion protocol_version )
    { if( protocol_version == record::PROTOCOL_VERSION_TLS13 ) m_tls13_supported = true; }
    void named_group( record::NamedGroup named_group );
    void signature_scheme( record::SignatureScheme );
    void key_share_entry( record::NamedGroup, const uint8_t*, uint16_t );

    [[nodiscard]]
    bool commit( TlsReadBuffer& buffer, KeyStore* domain_keys_store );

    crypto::TlsHandshake& m_tls_handshake;

    static constexpr uint32_t SIGNATURE_SCHEMES_ARRAY_SIZE = 15;
    uint16_t                signature_schemes_count = 0;
    record::SignatureScheme signature_schemes[SIGNATURE_SCHEMES_ARRAY_SIZE];

    record::LegacySessionId* legacy_session_container;
    record::CipherSuite m_cipher_suite = record::TLS_PRIVATE_CIPHER_SUITE;
    record::NamedGroup  m_supported_group = record::NamedGroup::TLS_PRIVATE_NAMED_GROUP;
    struct {
        record::NamedGroup named_group = record::NamedGroup::TLS_PRIVATE_NAMED_GROUP;
        uint16_t       data_size = {};
        const uint8_t* key_data  = {};
    } m_key_share;
    bool m_tls13_supported = false;

    ClientHelloHook() = delete;
    ClientHelloHook( const ClientHelloHook& ) = delete;
    ClientHelloHook( ClientHelloHook&& )      = delete;
    ClientHelloHook& operator=(const ClientHelloHook& ) = delete;
    ClientHelloHook& operator=(ClientHelloHook&& )      = delete;
};

inline void ClientHelloHook::client_hello_cipher_suites(
        const record::CipherSuite* cipher_suite, uint32_t size_in_bytes )
{
    for( uint32_t idx = 0; idx < size_in_bytes/sizeof(record::CipherSuite); ++idx )
    {
        if( crypto::TlsCipherSuite::is_supported_cipher_suite(cipher_suite[idx]) )
        {
            m_cipher_suite = cipher_suite[idx];
            break;
        }
    }
}
void ClientHelloHook::named_group( record::NamedGroup group )
{
    if( m_supported_group == record::NamedGroup::TLS_PRIVATE_NAMED_GROUP
        && crypto::DheGroup::is_supported(group) )
    {
        m_supported_group = group;
    }
}
void ClientHelloHook::key_share_entry( record::NamedGroup named_group, const uint8_t* key_data, uint16_t data_size )
{
    if( m_key_share.named_group == record::NamedGroup::TLS_PRIVATE_NAMED_GROUP
        && crypto::DheGroup::is_supported(named_group) )
    {
        m_key_share.named_group = named_group;
        m_key_share.key_data = key_data;
        m_key_share.data_size= data_size;
    }
}

bool ClientHelloHook::commit( TlsReadBuffer& buffer, KeyStore* domain_keys_store )
{
    if( !m_tls13_supported
        || m_cipher_suite == record::TLS_PRIVATE_CIPHER_SUITE
        || m_key_share.named_group == record::NamedGroup::TLS_PRIVATE_NAMED_GROUP )
    {
        // FIXME: send HelloRetryRequest if m_key_share.named_group is empty
        // but m_supported_group not
        return false;
    }
    m_tls_handshake.set_named_group( m_key_share.named_group );
    m_tls_handshake.set_tls_cipher_suite( m_cipher_suite );
    m_tls_handshake.add_message( record::handshake_message( buffer.head() )
                                 ,record::record_content_size( buffer.head() ) );

    m_tls_handshake.set_handshake_hello_key_share(
            m_key_share.named_group, m_key_share.key_data, m_key_share.data_size
    );

    m_tls_handshake.domain_keys = domain_keys_store->find( m_tls_handshake.accept_sni->c_str() );
    if( m_tls_handshake.domain_keys == nullptr )
        throw std::runtime_error( "ClientHelloHook::commit() failed find domain \""
                                  + *m_tls_handshake.accept_sni +"\"" );
    // find signature scheme for certificate
    m_tls_handshake.cert_signature_scheme = KeyStore::find_best_signature_scheme( signature_schemes, signature_schemes_count
                                                                                  , m_tls_handshake.domain_keys->signature_schemes );

    return true;
}

void ClientHelloHook::client_hello_legacy_session_id( const record::LegacySessionId* legacy_session_id ) const
{
    std::copy_n( reinterpret_cast<const uint8_t*>(legacy_session_id)
               , sizeof(record::LegacySessionId)+legacy_session_id->size
               , reinterpret_cast<uint8_t*>(legacy_session_container) );
}

void ClientHelloHook::signature_scheme( record::SignatureScheme scheme )
{
    if( KeyStore::is_supported_signature_scheme( scheme )
        && signature_schemes_count < SIGNATURE_SCHEMES_ARRAY_SIZE )
    {
        signature_schemes[signature_schemes_count++] = scheme;
    }
}
template< typename OS_SEAM, LogLevel LOG_LEVEL >
CoroutineAwaiter<bool> TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::read_client_hello_record(
        RecordLayer& record_layer,
        crypto::TlsHandshake& tls_handshake,
        record::Parser& parser, KeyStore* domain_keys_store )
{
    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;

    co_await record_layer.read_full_record_skip_change_cipher_spec(); // FIXME: check result
    if constexpr ( LOG_LEVEL >= LogLevel::NOTICE )
        record::print_net_record( read_buffer.head(), read_buffer.size() );

    auto encrypted_record_size = record::full_record_size( read_buffer.head() );

    if( ! record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != record::HandshakeType::CLIENT_HELLO )
        throw std::runtime_error( "TlsAcceptor::read_client_hello_record got unexpected handshake record "
                                  + std::to_string(static_cast<uint8_t>(handshake_type) ) );

    ClientHelloHook client_hello_hook{
            tls_handshake, reinterpret_cast<record::LegacySessionId*>(tls_handshake.legacy_session) };
    auto[bytes_parsed, err] = parser.parse_net_record( &client_hello_hook, read_buffer.head(), read_buffer.size() );
    if( err )
        throw std::runtime_error( "TlsAcceptor::read_client_hello_record() failed parse ClientHello message" );

    client_hello_hook.commit( read_buffer, domain_keys_store ); // FIXME: check result

    read_buffer.consume( encrypted_record_size );

    co_return true;
}

struct ClientFinishedHook : record::EmptyHook
{
    ClientFinishedHook( crypto::TlsHandshake* record_cryptor )
            : m_record_cryptor{record_cryptor}
    {}

    ClientFinishedHook() = delete;
    ClientFinishedHook( const ClientFinishedHook& ) = delete;
    ClientFinishedHook( ClientFinishedHook&& ) = delete;
    ClientFinishedHook& operator=( const ClientFinishedHook& ) = delete;
    ClientFinishedHook& operator=( ClientFinishedHook&& ) = delete;

    void finished_data( const uint8_t*, uint32_t );
    bool commit();

private:
    crypto::TlsHandshake* m_record_cryptor;
    const uint8_t* m_finished_data = nullptr;
    uint32_t       m_finished_data_size = 0;
};
inline void ClientFinishedHook::finished_data( const uint8_t* buffer, uint32_t buffer_size )
{
    m_finished_data = buffer;
    m_finished_data_size = buffer_size;
}

bool ClientFinishedHook::commit()
{
    uint8_t hmac_data[EVP_MAX_MD_SIZE];
    auto hmac_size = m_record_cryptor->handshake_finished_create_verify_data( hmac_data, false );
    if( (hmac_size != m_finished_data_size)
        || (::memcmp( m_finished_data, hmac_data, m_finished_data_size ) != 0) )
    {
        return false;
    }

    return true;
}

template< typename OS_SEAM, LogLevel LOG_LEVEL >
CoroutineAwaiter<bool> TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::read_client_finished_record(
        RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser )
{
    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;
    uint32_t encrypted_record_size = co_await record_layer.read_record_decrypt_and_skip_change_cipher();

    if( ! record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != record::HandshakeType::FINISHED )
        throw std::runtime_error( "TlsAcceptorImpl::read_client_finished_record got unexpected handshake record "
                                  + std::to_string(static_cast<uint8_t>(handshake_type) ) );

    ClientFinishedHook client_finished_hook{ &tls_handshake };
    auto[bytes_parsed, err] = parser.parse_net_record( &client_finished_hook, read_buffer.head(), read_buffer.size() );
    if( err )
        throw std::runtime_error( "TlsAcceptorImpl::read_client_finished_record() failed parse Finished message" );

    bool finished_verified = client_finished_hook.commit();
    if( !finished_verified )
        throw std::runtime_error( "Client Finished failed" );

    tls_handshake.add_message(
            record::handshake_message( read_buffer.head() ), record::record_content_size(read_buffer.head()) );
    read_buffer.consume( encrypted_record_size );

    co_return true;
}
template< typename OS_SEAM, LogLevel LOG_LEVEL >
uint32_t TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::produce_server_hello_record(
        TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake )
{
//    auto server_hello_record_size = RecordHelpers::server_hello_record_buffer_size(
//                record_layer, tls_handshake );

    auto server_hello_record_size = RecordHelpers::create_server_hello_record( tls_handshake, buffer.tail());
    if constexpr ( LOG_LEVEL >= LogLevel::NOTICE )
        record::print_net_record( buffer.tail(), server_hello_record_size );

    tls_handshake.add_message( record::handshake_message( buffer.tail() )
                               ,record::record_content_size( buffer.tail() ) );
    tls_handshake.derive_client_server_traffic_secrets( false );

    buffer.produce( server_hello_record_size );

    return server_hello_record_size;
}

template< typename OS_SEAM, LogLevel LOG_LEVEL >
uint32_t TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::produce_encrypted_extensions_record(
        TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake )
{
    auto encrypted_extensions_record_size = RecordHelpers::create_encrypted_extensions_record(
            tls_handshake, buffer.tail() );
    if constexpr ( LOG_LEVEL >= LogLevel::NOTICE )
        record::print_net_record( buffer.tail(), encrypted_extensions_record_size );

    tls_handshake.add_message( record::handshake_message( buffer.tail() )
                               ,record::record_content_size( buffer.tail() ) );

    auto encrypted_size = tls_handshake.m_record_cryptor.encrypt_record( buffer.tail()
                                                        , record::record_content_data( buffer.tail()), record::record_content_size( buffer.tail() ) );

    buffer.produce( encrypted_size );

    return encrypted_size;
}

template< typename OS_SEAM, LogLevel LOG_LEVEL >
uint32_t TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::produce_certificate_record(
        TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake )
{
    auto certificate_record_size = RecordHelpers::create_certificate_record( tls_handshake, buffer.tail() );
    if constexpr ( LOG_LEVEL >= LogLevel::NOTICE )
        record::print_net_record( buffer.tail(), certificate_record_size );

    tls_handshake.add_message( record::handshake_message( buffer.tail() )
                               ,record::record_content_size( buffer.tail() ) );

    auto encrypted_size = tls_handshake.m_record_cryptor.encrypt_record( buffer.tail()
                                                        , record::record_content_data( buffer.tail() )
                                                        , record::record_content_size( buffer.tail() ) );

    buffer.produce( encrypted_size );

    return encrypted_size;
}

template< typename OS_SEAM, LogLevel LOG_LEVEL >
uint32_t TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::produce_certificate_verify_record(
        TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake )
{
    auto certificate_verify_record_size = RecordHelpers::create_certificate_verify_record(
            tls_handshake, buffer.tail() );
    if constexpr ( LOG_LEVEL >= LogLevel::NOTICE )
        record::print_net_record( buffer.tail(), certificate_verify_record_size );

    tls_handshake.add_message( record::handshake_message( buffer.tail() )
                               ,record::record_content_size( buffer.tail() ) );

    auto encrypted_size = tls_handshake.m_record_cryptor.encrypt_record( buffer.tail()
                                                        , record::record_content_data( buffer.tail()), record::record_content_size( buffer.tail() ) );

    buffer.produce( encrypted_size );

    return encrypted_size;
}

template< typename OS_SEAM, LogLevel LOG_LEVEL >
uint32_t TlsAcceptorImpl<OS_SEAM,LOG_LEVEL>::produce_server_finished_record(
        TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake )
{
    auto finished_record_size = RecordHelpers::create_server_finished_record(
            tls_handshake, buffer.tail() );
    if constexpr ( LOG_LEVEL >= LogLevel::NOTICE )
        record::print_net_record( buffer.tail(), finished_record_size );

    tls_handshake.add_message( record::handshake_message( buffer.tail() )
                               ,record::record_content_size( buffer.tail() ) );

    auto encrypted_size = tls_handshake.m_record_cryptor.encrypt_record(
            buffer.tail(), record::record_content_data( buffer.tail() )
            , record::record_content_size( buffer.tail() ) );

    buffer.produce( encrypted_size );

    return encrypted_size;
}

}
