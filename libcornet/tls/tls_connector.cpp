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

#include <libcornet/tls/tls_connector.hpp>

#include <deque>
#include <cassert>

#include <libcornet/tls/parser.hpp>
#include <libcornet/tls/tls_trusted_certs.hpp>
#include <libcornet/tls/record_helpers.hpp>
#include <libcornet/tls/crypto/tls_handshake.hpp>

namespace pioneer19::cornet::tls13
{

uint32_t TlsConnector::produce_client_hello_record(
        TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake )
{
//    auto server_hello_record_size = RecordHelpers::server_hello_record_buffer_size(
//                record_layer, tls_handshake );

    auto client_hello_record_size = RecordHelpers::client_hello_record_buffer_size( tls_handshake );
    auto size2 = RecordHelpers::create_client_hello_record( tls_handshake, buffer.tail() );
    assert( client_hello_record_size == size2 );
    record::print_net_record( buffer.tail(), client_hello_record_size );

    buffer.produce( client_hello_record_size );

    return client_hello_record_size;
}

struct ServerHelloHook : record::EmptyHook
{
    explicit ServerHelloHook( crypto::TlsHandshake* record_cryptor )
            : m_record_cryptor{record_cryptor}{}
    // hooks
    void server_hello_cipher_suites( const record::CipherSuite*, uint32_t cs_size );
    void key_share_entry( record::NamedGroup, const uint8_t*, uint16_t );

    void commit();

    crypto::TlsHandshake* m_record_cryptor;
    // key_share cache
    record::NamedGroup  m_key_share_named_group = record::NamedGroup::TLS_PRIVATE_NAMED_GROUP;
    uint16_t            m_key_share_pub_key_size = 0;
    const uint8_t*      m_key_share_pub_key = nullptr;

    ServerHelloHook() = delete;
    ServerHelloHook(const ServerHelloHook& ) = delete;
    ServerHelloHook(ServerHelloHook&& ) = delete;
    ServerHelloHook& operator=(const ServerHelloHook&) = delete;
    ServerHelloHook& operator=(ServerHelloHook&&) = delete;
};

void ServerHelloHook::key_share_entry( record::NamedGroup named_group
        ,const uint8_t* public_key, uint16_t key_size )
{
    m_key_share_named_group = named_group;
    m_key_share_pub_key = public_key;
    m_key_share_pub_key_size = key_size;
}

void ServerHelloHook::server_hello_cipher_suites(
        const record::CipherSuite* cipher_suites, uint32_t )
{
    m_record_cryptor->set_tls_cipher_suite( cipher_suites[0] );
}

void ServerHelloHook::commit()
{
    m_record_cryptor->set_handshake_hello_key_share(
            m_key_share_named_group, m_key_share_pub_key, m_key_share_pub_key_size );
    m_record_cryptor->derive_client_server_traffic_secrets( true );
}

coroutines::CoroutineAwaiter<bool> TlsConnector::read_server_hello_record(
        RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser )
{
    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;

    co_await record_layer.read_full_record_skip_change_cipher_spec(); // FIXME: check result
    record::print_net_record( read_buffer.head(), read_buffer.size() );
    auto record_size = record::full_record_size( read_buffer.head() );

    if( ! record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != record::HandshakeType::SERVER_HELLO )
        throw std::runtime_error( "TlsConnector::read_server_hello_record() got unexpected handshake record"
                                  + std::to_string(static_cast<uint8_t>(handshake_type) ) );

    ServerHelloHook server_hello_hook{&tls_handshake}; // FIXME: cryptor! not handshake
    auto[bytes_parsed, err] = parser.parse_net_record( &server_hello_hook, read_buffer.head(), read_buffer.size() );
    if( err )
        throw std::runtime_error( "TlsConnector::read_server_hello_record() failed parse server response" );

    // add to transcript hash ClientHello from write_buffer
    TlsWriteBuffer& write_buffer = record_layer.m_write_buffer;
    tls_handshake.add_message( record::handshake_message( write_buffer.head() )
                               ,record::record_content_size( write_buffer.head()) );
    write_buffer.consume( record::full_record_size(write_buffer.head()) );

    tls_handshake.add_message( record::handshake_message( read_buffer.head() )
                               ,record::record_content_size( read_buffer.head()) );
    server_hello_hook.commit();
    read_buffer.consume( record_size );

    co_return true;
}

coroutines::CoroutineAwaiter<bool>
TlsConnector::read_encrypted_extensions_record(
        RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser )
{
    uint32_t encrypted_record_size = co_await record_layer.read_record_decrypt_and_skip_change_cipher();

    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;
    if( !record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != record::HandshakeType::ENCRYPTED_EXTENSIONS )
    {
        throw std::runtime_error(
                "TlsConnector::read_encrypted_extensions_record() got unexpected handshake record "
                + std::to_string( static_cast<uint8_t>(handshake_type) )
                + "expected " + std::to_string(
                        static_cast<uint8_t>(record::HandshakeType::ENCRYPTED_EXTENSIONS) ) );
    }

    tls_handshake.add_message( record::handshake_message( read_buffer.head() )
                               ,record::record_content_size( read_buffer.head()) );
    read_buffer.consume( encrypted_record_size );

    co_return true;
}
struct CertificateHook : record::EmptyHook
{
    explicit CertificateHook( crypto::TlsHandshake* record_cryptor )
            : m_record_cryptor{record_cryptor}
    {}

    CertificateHook() = delete;
    CertificateHook( const CertificateHook& ) = delete;
    CertificateHook( CertificateHook&& ) = delete;
    CertificateHook& operator=( const CertificateHook& ) = delete;
    CertificateHook& operator=( CertificateHook&& ) = delete;

    void cert_data(  record::CertificateType, const uint8_t*, uint32_t );
    bool commit();

private:
    static bool verify_certificate( X509_STORE* trusted_store, X509* cert
            ,STACK_OF(X509)* cert_chain_stack, const std::string& hostname );

    crypto::TlsHandshake* m_record_cryptor;
    std::deque<std::pair<const uint8_t*,uint32_t>> m_certs_buffers;
};

void CertificateHook::cert_data( record::CertificateType
        ,const uint8_t* cert_data, uint32_t data_size )
{
    m_certs_buffers.emplace_back( cert_data, data_size );
}

bool CertificateHook::commit()
{
    if( m_certs_buffers.empty() )
        return false;

    const uint8_t* cert_data = m_certs_buffers.front().first;
    uint32_t data_size       = m_certs_buffers.front().second;
    X509* host_certificate = d2i_X509( nullptr, &cert_data, data_size );
    if( host_certificate == nullptr )
        return false;
    m_record_cryptor->handshake_set_certificate( host_certificate );
    m_certs_buffers.pop_front();

    STACK_OF( X509 )* cert_chain_stack = sk_X509_new_null();
    for( auto& cert_pair : m_certs_buffers )
    {
        cert_data = cert_pair.first;
        data_size = cert_pair.second;

        X509* x = d2i_X509( nullptr, &cert_data, data_size );
        if( x == nullptr )
        {
            sk_X509_pop_free( cert_chain_stack, X509_free );
            return false;
        }
        sk_X509_push( cert_chain_stack, x );
    }
    m_certs_buffers.clear();
    bool verify_res = verify_certificate( TlsTrustedCerts::store_instance()
                                          ,host_certificate, cert_chain_stack, *m_record_cryptor->connect_sni );

    sk_X509_pop_free(cert_chain_stack, X509_free);

    return verify_res;
}

bool CertificateHook::verify_certificate( X509_STORE* trusted_store, X509* cert
        ,STACK_OF(X509)* cert_chain_stack, const std::string& hostname )
{
    X509_STORE_CTX* verify_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init( verify_ctx, trusted_store, cert, cert_chain_stack);

    X509_VERIFY_PARAM* verify_param = X509_STORE_CTX_get0_param( verify_ctx );
    X509_VERIFY_PARAM_add1_host( verify_param, hostname.c_str(), hostname.size() );
    // X509_VERIFY_PARAM_set_flags( verify_param, X509_V_FLAG_PARTIAL_CHAIN );

    int verify_res = X509_verify_cert( verify_ctx );
    if( verify_res <= 0 )
    {
        printf( "verify error: %s\n"
                ,X509_verify_cert_error_string(X509_STORE_CTX_get_error(verify_ctx) ) );
    }

    X509_STORE_CTX_free( verify_ctx );

    return verify_res > 0;
}

coroutines::CoroutineAwaiter<bool>
TlsConnector::read_certificate_record( RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake,
                                       record::Parser& parser )
{
    uint32_t encrypted_record_size = co_await record_layer.read_record_decrypt_and_skip_change_cipher();

    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;
    if( ! record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType expected_handshake_type = record::HandshakeType::CERTIFICATE;
    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != expected_handshake_type )
    {
        throw std::runtime_error(
                "TlsConnector::read_encrypted_extensions_record() got unexpected handshake record "
                + std::to_string( static_cast<uint8_t>(handshake_type) )
                + "expected " + std::to_string( static_cast<uint8_t>(expected_handshake_type) ) );
    }

    CertificateHook certificate_hook{&tls_handshake}; // FIXME: cryptor! not handshake
    auto[bytes_parsed, err] = parser.parse_net_record( &certificate_hook, read_buffer.head(), read_buffer.size() );
    if( err )
        throw std::runtime_error( "TlsConnector::read_server_hello_record() failed parse server response" );
    certificate_hook.commit();

    tls_handshake.add_message( record::handshake_message( read_buffer.head() )
                               ,record::record_content_size( read_buffer.head()) );

    read_buffer.consume( encrypted_record_size );

    co_return true;
}
struct CertificateVerifyHook : record::EmptyHook
{
    CertificateVerifyHook( crypto::TlsHandshake* record_cryptor )
            : m_record_cryptor{record_cryptor}
    {}

    CertificateVerifyHook() = delete;
    CertificateVerifyHook( const CertificateVerifyHook& ) = delete;
    CertificateVerifyHook( CertificateVerifyHook&& ) = delete;
    CertificateVerifyHook& operator=( const CertificateVerifyHook& ) = delete;
    CertificateVerifyHook& operator=( CertificateVerifyHook&& ) = delete;

    void cert_verify_data( const record::SignatureScheme*, const uint8_t*, uint32_t );
    bool commit();

private:
    crypto::TlsHandshake* m_record_cryptor;
    const record::SignatureScheme* m_signature_scheme = nullptr;
    const uint8_t* m_signature = nullptr;
    uint32_t m_signature_size = 0;
};

inline void CertificateVerifyHook::cert_verify_data( const record::SignatureScheme* signature_scheme
        ,const uint8_t* buffer, uint32_t buffer_size )
{
    m_signature_scheme = signature_scheme;
    m_signature = buffer;
    m_signature_size = buffer_size;
}

inline bool CertificateVerifyHook::commit()
{
    return m_record_cryptor->handshake_certificate_verify_do_verify_signature(
            *m_signature_scheme, m_signature, m_signature_size );
}

coroutines::CoroutineAwaiter<bool>
TlsConnector::read_certificate_verify_record( RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake,
                                              record::Parser& parser )
{
    uint32_t encrypted_record_size = co_await record_layer.read_record_decrypt_and_skip_change_cipher();

    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;
    if( ! record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType expected_handshake_type = record::HandshakeType::CERTIFICATE_VERIFY;
    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != expected_handshake_type )
    {
        throw std::runtime_error(
                "TlsConnector::read_encrypted_extensions_record() got unexpected handshake record "
                + std::to_string( static_cast<uint8_t>(handshake_type) )
                + "expected " + std::to_string( static_cast<uint8_t>(expected_handshake_type) ) );
    }

    CertificateVerifyHook certificate_verify_hook{&tls_handshake}; // FIXME: cryptor! not handshake
    auto[bytes_parsed, err] = parser.parse_net_record( &certificate_verify_hook, read_buffer.head(), read_buffer.size() );
    if( err )
        throw std::runtime_error( "TlsConnector::read_server_hello_record() failed parse server response" );
    certificate_verify_hook.commit();

    tls_handshake.add_message( record::handshake_message( read_buffer.head() )
                               ,record::record_content_size( read_buffer.head()) );
    read_buffer.consume( encrypted_record_size );

    co_return true;
}

struct ServerFinishedHook : record::EmptyHook
{
    ServerFinishedHook( crypto::TlsHandshake* record_cryptor )
            : m_record_cryptor{record_cryptor}
    {}

    void finished_data( const uint8_t*, uint32_t );
    bool commit();

    ServerFinishedHook() = delete;
    ServerFinishedHook( const ServerFinishedHook& ) = delete;
    ServerFinishedHook( ServerFinishedHook&& ) = delete;
    ServerFinishedHook& operator=( const ServerFinishedHook& ) = delete;
    ServerFinishedHook& operator=( ServerFinishedHook&& ) = delete;

private:
    crypto::TlsHandshake* m_record_cryptor = nullptr;
    const uint8_t* m_finished_data = nullptr;
    uint32_t m_finished_data_size = 0;
};
inline void ServerFinishedHook::finished_data( const uint8_t* buffer, uint32_t buffer_size )
{
    m_finished_data = buffer;
    m_finished_data_size = buffer_size;
}

bool ServerFinishedHook::commit()
{
    uint8_t hmac_data[EVP_MAX_MD_SIZE];
    auto hmac_size = m_record_cryptor->handshake_finished_create_verify_data( hmac_data );
    if( (hmac_size != m_finished_data_size)
        || (::memcmp( m_finished_data, hmac_data, m_finished_data_size ) != 0) )
    {
        return false;
    }

    return true;
}
coroutines::CoroutineAwaiter<bool>
TlsConnector::read_server_finished_record( RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake,
                                           record::Parser& parser )
{
    uint32_t encrypted_record_size = co_await record_layer.read_record_decrypt_and_skip_change_cipher();

    TlsReadBuffer& read_buffer = record_layer.m_read_buffer;
    if( ! record::is_handshake_record( read_buffer.head() ) )
        co_return false; // FIXME: probably need to send some Alert

    record::HandshakeType expected_handshake_type = record::HandshakeType::FINISHED;
    record::HandshakeType handshake_type = record::record_handshake_type( read_buffer.head() );
    if( handshake_type != expected_handshake_type )
    {
        throw std::runtime_error(
                "TlsConnector::read_encrypted_extensions_record() got unexpected handshake record "
                + std::to_string( static_cast<uint8_t>(handshake_type) )
                + "expected " + std::to_string( static_cast<uint8_t>(expected_handshake_type) ) );
    }

    ServerFinishedHook finished_hook{&tls_handshake};
    auto[bytes_parsed, err] = parser.parse_net_record( &finished_hook, read_buffer.head(), read_buffer.size() );
    if( err )
        throw std::runtime_error( "TlsConnector::read_server_hello_record() failed parse server response" );
    finished_hook.commit();

    tls_handshake.add_message( record::handshake_message( read_buffer.head() )
                               ,record::record_content_size( read_buffer.head()) );

    read_buffer.consume( encrypted_record_size );

    co_return true;
}

coroutines::CoroutineAwaiter<uint32_t> TlsConnector::send_client_finished_record(
        RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake )
{
    uint8_t* buffer = record_layer.m_write_buffer.tail();
    uint32_t rec_size_calculated = RecordHelpers::client_finished_record_buffer_size( tls_handshake );
    uint32_t rec_size = RecordHelpers::create_client_finished_record( tls_handshake, buffer );

    assert( rec_size == rec_size_calculated );
    record::print_net_record( buffer, rec_size );
    tls_handshake.add_message( record::handshake_message(buffer), record::record_content_size(buffer) );

    rec_size = co_await record_layer.encrypt_and_send_record(
            record::handshake_message(buffer), record::record_content_size(buffer) );

    co_return rec_size;
}

coroutines::CoroutineAwaiter<bool> RecordLayer::tls_connect( Poller& poller, const char* hostname, uint16_t port
        , const std::string& sni )
{
    if( !co_await m_socket.async_connect( poller, hostname, port ) )
        co_return false;

    crypto::RecordCryptor& record_cryptor = m_cryptor;
    crypto::TlsHandshake  tls_handshake{ record_cryptor, sni, record::NamedGroup::X25519 };
    tls_handshake.m_hello_type = crypto::TlsHandshake::HelloType::ClientHello;

    uint32_t record_size = TlsConnector::produce_client_hello_record( m_write_buffer, tls_handshake );

    auto bytes_sent = co_await m_socket.async_write( m_write_buffer.head(), record_size );
    printf( "RecordLayer::tls_connect sent %ld bytes\n", bytes_sent );
    // ClientHello Must wait in write buffer until ServerHello will be read and hash method get known

    record::Parser parser;
    if( !co_await TlsConnector::read_server_hello_record( *this, tls_handshake, parser ) )
    {
        throw std::runtime_error(
                "RecordLayer::tls_connect got record type "
                + std::to_string( static_cast<uint8_t>(
                        record::record_content_type( m_read_buffer.head()))));
    }
    if( !co_await TlsConnector::read_encrypted_extensions_record( *this, tls_handshake, parser ))
    {
        throw std::runtime_error(
                "RecordLayer::tls_connect got record type "
                + std::to_string( static_cast<uint8_t>(
                        record::record_content_type( m_read_buffer.head()))));
    }
    if( !co_await TlsConnector::read_certificate_record( *this, tls_handshake, parser ))
    {
        throw std::runtime_error(
                "RecordLayer::tls_connect got record type "
                + std::to_string( static_cast<uint8_t>(record::record_content_type( m_read_buffer.head()))));
    }
    if( !co_await TlsConnector::read_certificate_verify_record( *this, tls_handshake, parser ))
    {
        throw std::runtime_error(
                "RecordLayer::tls_connect got record type "
                + std::to_string( static_cast<uint8_t>(record::record_content_type( m_read_buffer.head()))));
    }
    if( !co_await TlsConnector::read_server_finished_record( *this, tls_handshake, parser ))
    {
        throw std::runtime_error(
                "RecordLayer::tls_connect got record type "
                + std::to_string( static_cast<uint8_t>(record::record_content_type(
                        m_read_buffer.head()))));
    }

    uint8_t server_finished_transcript_hash[ EVP_MAX_MD_SIZE ]; // ClientHello...server Finished
    tls_handshake.current_transcript_hash( server_finished_transcript_hash );

    co_await TlsConnector::send_client_finished_record( *this, tls_handshake );

    uint8_t client_finished_transcript_hash[ EVP_MAX_MD_SIZE ]; // ClientHello...client Finished
    tls_handshake.current_transcript_hash( client_finished_transcript_hash );

    create_application_traffic_cryptor(
            tls_handshake, server_finished_transcript_hash, client_finished_transcript_hash, false );
    co_return true;
}

}
