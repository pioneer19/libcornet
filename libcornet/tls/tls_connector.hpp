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
class TlsConnector
{
public:
    ~TlsConnector() = default;

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

    TlsConnector() = delete;
    TlsConnector( const TlsConnector& ) = delete;
    TlsConnector( TlsConnector&& ) = delete;
    TlsConnector& operator=( TlsConnector&& ) = delete;
    TlsConnector& operator=( const TlsConnector& ) = delete;
};

}
