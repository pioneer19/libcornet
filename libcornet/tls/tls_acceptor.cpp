/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tls/tls_acceptor.hpp>
#include <libcornet/tls/tls_acceptor_template.cpp>

namespace pioneer19::cornet::tls13
{
template class TlsAcceptorImpl<PRODUCTION_OS_SEAM>;

coroutines::CoroutineAwaiter<TlsSocket> RecordLayer::tls_accept(
        Poller& poller, sockaddr_in6* peer_addr, KeyStore* keys_store )
{
    TcpSocket client_sock = co_await m_socket.async_accept( poller, peer_addr );

    RecordLayer record_layer{ std::move(client_sock) };
    TlsReadBuffer&  read_buffer  = record_layer.m_read_buffer;
    TlsWriteBuffer& write_buffer = record_layer.m_write_buffer;
    crypto::RecordCryptor& record_cryptor = record_layer.m_cryptor;

    std::string server_name;
    crypto::TlsHandshake tls_handshake{record_cryptor, server_name};
    record::Parser parser;
    // this MUST be ClientHello unencrypted record
    if( !co_await TlsAcceptor::read_client_hello_record(
                record_layer, tls_handshake, parser, keys_store ) )
    {
        throw std::runtime_error(
                "TlsServer::async_accept got record type "
                + std::to_string( static_cast<uint8_t>(record::record_content_type( read_buffer.head()))) );
    }

    tls_handshake.m_hello_type = crypto::TlsHandshake::HelloType::ServerHello;
    uint32_t record_size = TlsAcceptor::produce_server_hello_record( write_buffer, tls_handshake );
    record_size = TlsAcceptor::produce_encrypted_extensions_record( write_buffer, tls_handshake );
    record_size = TlsAcceptor::produce_certificate_record( write_buffer, tls_handshake );
    record_size = TlsAcceptor::produce_certificate_verify_record( write_buffer, tls_handshake );
    record_size = TlsAcceptor::produce_server_finished_record( write_buffer, tls_handshake );

    uint32_t bytes_sent = co_await record_layer.async_write_buffer();
    printf( "TlsServer::async_accept() sent %d bytes\n", bytes_sent );


    uint8_t server_finished_transcript_hash[ EVP_MAX_MD_SIZE ]; // ClientHello...server Finished
    tls_handshake.current_transcript_hash( server_finished_transcript_hash );

    if( !co_await TlsAcceptor::read_client_finished_record(record_layer, tls_handshake, parser ) )
    {
        throw std::runtime_error(
                "TlsServer::async_accept got record type instead of client finished "
                + std::to_string( static_cast<uint8_t>(record::record_content_type( read_buffer.head()))));
    }

    uint8_t client_finished_transcript_hash[ EVP_MAX_MD_SIZE ]; // ClientHello...client Finished
    tls_handshake.current_transcript_hash( client_finished_transcript_hash );

    record_layer.create_application_traffic_cryptor(
            tls_handshake, server_finished_transcript_hash, client_finished_transcript_hash, true );

    co_return TlsSocket{ std::move(record_layer) };
}

}
