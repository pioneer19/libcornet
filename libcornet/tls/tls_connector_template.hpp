/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <libcornet/tls/parser.hpp>
#include <libcornet/tls/tls_read_buffer.hpp>
#include <libcornet/tls/record_layer.hpp>
#include <libcornet/tls/crypto/record_cryptor.hpp>

#include <libcornet/coroutines_utils.hpp>

namespace pioneer19::cornet::tls13
{

/**
 * @brief helper functions to process tls handshake on server side
 */
template< typename OS_SEAM >
class TlsConnectorImpl
{
public:
    ~TlsConnectorImpl() = default;

    static coroutines::CoroutineAwaiter<bool> read_server_hello_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser );
    static coroutines::CoroutineAwaiter<bool> read_encrypted_extensions_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser );
    static coroutines::CoroutineAwaiter<bool> read_certificate_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser );
    static coroutines::CoroutineAwaiter<bool> read_certificate_verify_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser );
    static coroutines::CoroutineAwaiter<bool> read_server_finished_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser );

    static uint32_t produce_client_hello_record( TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake );
    static coroutines::CoroutineAwaiter<uint32_t> send_client_finished_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake );

    TlsConnectorImpl() = delete;
    TlsConnectorImpl( const TlsConnectorImpl& ) = delete;
    TlsConnectorImpl( TlsConnectorImpl&& ) = delete;
    TlsConnectorImpl& operator=( TlsConnectorImpl&& ) = delete;
    TlsConnectorImpl& operator=( const TlsConnectorImpl& ) = delete;
};

}
