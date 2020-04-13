/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <cstdint>

#include <string>

#include <libcornet/tcp_socket.hpp>
#include <libcornet/tls/tls_read_buffer.hpp>
#include <libcornet/tls/crypto/record_cryptor.hpp>
#include <libcornet/tls/parser.hpp>
#include <libcornet/tls/key_store.hpp>
#include <libcornet/coroutines_utils.hpp>

namespace pioneer19::cornet::tls13
{
class TlsSocket;

/**
 * @brief Low level state machine for reading and writing tls records
 */
class RecordLayer
{
public:
    RecordLayer()  = default;
    ~RecordLayer() = default;
    RecordLayer( RecordLayer&& )            = default;
    RecordLayer& operator=( RecordLayer&& ) = default;

    explicit RecordLayer( TcpSocket&& socket ) : m_socket{std::move(socket)} {}

    void bind( const char* ip_address, uint16_t port ) {m_socket.bind(ip_address,port);}
    void listen( Poller& poller ) {m_socket.listen(poller);}
    coroutines::CoroutineAwaiter<TlsSocket> tls_accept(
            Poller& poller, sockaddr_in6* peer_addr, KeyStore* keys_store );
    [[nodiscard]]
    coroutines::CoroutineAwaiter<bool>     tls_connect( Poller& poller, const char* hostname, uint16_t port
            , const std::string& sni );
    /**
     * receive data from Tls socket to buffer until got minimum min_threshold bytes, buffer_size is max threshold
     * @param buffer buffer for data
     * @param buffer_size max data size to read
     * @param min_threshold min data_size to red
     * @return received data size
     */
    coroutines::CoroutineAwaiter<uint32_t> async_read(
            void* user_buffer, uint32_t buffer_size, uint32_t min_threshold = 1 );
    coroutines::CoroutineAwaiter<void>     async_write( const void* buffer, uint32_t buffer_size );

    RecordLayer( const RecordLayer& )       = delete;
    RecordLayer& operator=( const RecordLayer& ) = delete;

private:
    friend class TlsConnector;
    template<typename T>
    friend class TlsAcceptorImpl;

    uint16_t decrypt_record( uint8_t* buffer, crypto::RecordCryptor& cryptor );

    void create_application_traffic_cryptor( crypto::TlsHandshake& tls_handshake,
                                             const uint8_t* server_finished_transcript_hash,
                                             const uint8_t* client_finished_transcript_hash,
                                             bool sender_is_server );
    coroutines::CoroutineAwaiter<void> read_full_record();
    coroutines::CoroutineAwaiter<void> read_full_record_skip_change_cipher_spec();
    coroutines::CoroutineAwaiter <uint32_t> read_and_decrypt_record();
    coroutines::CoroutineAwaiter <uint32_t> read_record_decrypt_and_skip_change_cipher();

    coroutines::CoroutineAwaiter <uint32_t> async_write_buffer();
    coroutines::CoroutineAwaiter<void> encrypt_and_send_application_data( const void* buffer, uint32_t chunk_size );
    coroutines::CoroutineAwaiter<uint32_t> encrypt_and_send_record( const void* buffer, uint32_t chunk_size );

    TcpSocket      m_socket;
    TlsReadBuffer  m_read_buffer;
    TlsWriteBuffer m_write_buffer;
    crypto::RecordCryptor m_cryptor;
};

inline void RecordLayer::create_application_traffic_cryptor(
        crypto::TlsHandshake& tls_handshake,
        const uint8_t* server_finished_transcript_hash,
        const uint8_t* client_finished_transcript_hash,
        bool sender_is_server )
{
    m_cryptor.set_application_traffic_secrets( tls_handshake
            , server_finished_transcript_hash, client_finished_transcript_hash, sender_is_server );
}

}
