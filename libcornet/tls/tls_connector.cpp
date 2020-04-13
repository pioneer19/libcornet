/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tls/tls_connector.hpp>
#include <libcornet/tls/tls_connector_template.cpp>

namespace pioneer19::cornet::tls13
{

template class TlsConnectorImpl<PRODUCTION_OS_SEAM>;

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
